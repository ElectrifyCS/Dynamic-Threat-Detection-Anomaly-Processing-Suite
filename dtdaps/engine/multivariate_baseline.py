"""
multivariate_baseline.py

Online multivariate Gaussian baseline with Mahalanobis-distance anomaly
scoring. This is the k-dimensional generalization of AdaptiveThreshold:
instead of flagging when one signal deviates from its own mean, it flags
when the *joint* observation sits far from the learned correlation
structure between signals.

Why this exists: two signals can each look individually normal (neither
crosses its own z-score threshold) while their combination is a clear
anomaly — e.g. moderate file-modification rate + moderate entropy delta
happening together (intermittent-encryption evasion). AdaptiveThreshold,
run independently per signal, is blind to that by construction; it has
no notion of covariance between signals.

Same "sensitivity" semantics as AdaptiveThreshold on purpose: sensitivity
= 3.0 here produces the same false-positive rate as a univariate z=3.0
threshold, regardless of how many signals (k) are combined. Without this
correction, a raw Mahalanobis threshold needs to grow with k, which would
make "sensitivity" mean something different in every detector.
"""

from dataclasses import dataclass, field
import math

from .anomaly_engine import z_to_score


def _std_normal_cdf(x: float) -> float:
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


def _norm_ppf(p: float) -> float:
    """
    Inverse standard normal CDF (Acklam's rational approximation).
    Good to ~1e-9 absolute error. Pure Python — keeps this project's
    zero-third-party-dependency guarantee.
    """
    if not 0.0 < p < 1.0:
        raise ValueError("p must be in (0, 1)")

    a = [-3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02,
         1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00]
    b = [-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02,
         6.680131188771972e+01, -1.328068155288572e+01]
    c = [-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00,
         -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00]
    d = [7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00,
         3.754408661907416e+00]

    p_low, p_high = 0.02425, 1 - 0.02425

    if p < p_low:
        q = math.sqrt(-2 * math.log(p))
        return (((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / \
               ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    elif p <= p_high:
        q = p - 0.5
        r = q * q
        return (((((a[0]*r+a[1])*r+a[2])*r+a[3])*r+a[4])*r+a[5])*q / \
               (((((b[0]*r+b[1])*r+b[2])*r+b[3])*r+b[4])*r+1)
    else:
        q = math.sqrt(-2 * math.log(1 - p))
        return -(((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / \
                ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)


def chi2_quantile(p: float, k: int) -> float:
    """
    Wilson-Hilferty approximation of the chi-squared quantile function.
    Within ~1-2% of the exact value for k >= 2 (verified numerically
    against the closed-form k=2 case) — more than enough precision for
    a threshold this codebase already treats as a tunable heuristic.
    """
    z = _norm_ppf(p)
    term = 1 - (2.0 / (9 * k)) + z * math.sqrt(2.0 / (9 * k))
    return k * (term ** 3)


def sensitivity_to_mahalanobis_threshold(sensitivity: float, k: int) -> float:
    """
    Converts a univariate z-score sensitivity into the squared
    Mahalanobis-distance threshold for k dimensions carrying the same
    false-positive rate. k=1 returns exactly sensitivity**2 (exact, not
    approximated) so this is a strict generalization of
    AdaptiveThreshold's `abs(z) >= sensitivity` rather than a different
    rule that happens to agree at the edges.
    """
    if k == 1:
        return sensitivity ** 2
    p_tail = 2 * (1 - _std_normal_cdf(sensitivity))  # two-sided, matches AdaptiveThreshold
    return chi2_quantile(1 - p_tail, k)


def _invert_matrix(m: list) -> list:
    """
    Gauss-Jordan matrix inverse with partial pivoting. Pure Python, no
    numpy — keeps the zero-dependency guarantee. Intended for the small
    (2-6 dim) feature vectors detectors actually combine, not general
    numerical linear algebra.
    """
    n = len(m)
    aug = [row[:] + [1.0 if i == j else 0.0 for j in range(n)] for i, row in enumerate(m)]

    for col in range(n):
        pivot_row = max(range(col, n), key=lambda r: abs(aug[r][col]))
        if abs(aug[pivot_row][col]) < 1e-12:
            raise ValueError("Singular covariance matrix — needs more samples or a higher variance_floor")
        aug[col], aug[pivot_row] = aug[pivot_row], aug[col]

        pivot = aug[col][col]
        aug[col] = [v / pivot for v in aug[col]]

        for r in range(n):
            if r != col:
                factor = aug[r][col]
                aug[r] = [a - factor * b for a, b in zip(aug[r], aug[col])]

    return [row[n:] for row in aug]


@dataclass
class MultivariateGaussianBaseline:
    """
    Online mean vector + covariance matrix for k correlated signals, with
    Mahalanobis-distance anomaly scoring. EMA-updated (mirrors
    AdaptiveThreshold's non-stationary mode) so it tracks legitimate
    concept drift in the *relationship* between signals, not just their
    individual values.
    """
    k: int
    sensitivity: float = 3.0
    min_samples: int = 30
    decay: float = 0.05
    variance_floor: float = 0.01  # diagonal regularization

    def __post_init__(self):
        self._count = 0
        self._mean = [0.0] * self.k
        self._cov = [[0.0] * self.k for _ in range(self.k)]
        self._threshold = sensitivity_to_mahalanobis_threshold(self.sensitivity, self.k)

    def _regularized_cov(self) -> list:
        # Floor the diagonal so a tight early window — or a signal
        # that's legitimately near-constant — doesn't produce a
        # near-singular matrix or an artificially inflated distance.
        # Same motivation as AdaptiveThreshold.min_std_floor,
        # generalized to a matrix.
        cov = [row[:] for row in self._cov]
        for i in range(self.k):
            cov[i][i] = max(cov[i][i], self.variance_floor)
        return cov

    def mahalanobis_sq(self, vector: list) -> float:
        delta = [v - m for v, m in zip(vector, self._mean)]
        inv = _invert_matrix(self._regularized_cov())
        temp = [sum(inv[i][j] * delta[j] for j in range(self.k)) for i in range(self.k)]
        return sum(delta[i] * temp[i] for i in range(self.k))

    def evaluate_and_update(self, vector: list) -> tuple:
        """
        Check vector against the *current* baseline, then fold it in.
        Same update-after-check ordering as AdaptiveThreshold, and same
        caveat: this protects a single observation from diluting its own
        score, it does not by itself stop a sustained drift from
        eventually shifting the baseline over many observations.
        """
        has_baseline = self._count >= self.min_samples
        if has_baseline:
            d2 = self.mahalanobis_sq(vector)
            flagged = d2 >= self._threshold
        else:
            d2 = 0.0
            flagged = False

        self._count += 1
        if self._count == 1:
            self._mean = list(vector)
        else:
            delta = [v - m for v, m in zip(vector, self._mean)]
            self._mean = [m + self.decay * d for m, d in zip(self._mean, delta)]
            delta2 = [v - m for v, m in zip(vector, self._mean)]
            for i in range(self.k):
                for j in range(self.k):
                    self._cov[i][j] = (1 - self.decay) * (
                        self._cov[i][j] + self.decay * delta[i] * delta2[j]
                    )

        return flagged, d2

    @property
    def distance_threshold(self) -> float:
        return self._threshold

    @property
    def mean(self) -> list:
        return list(self._mean)


@dataclass
class MultivariateAnomalyResult:
    raw_vector: list
    mahalanobis_sq: float
    anomaly_score: float  # 0-1, same z_to_score sigmoid as the univariate engine
    is_anomaly: bool


@dataclass
class MultivariateAnomalyEngine:
    """Joint-signal counterpart to AnomalyEngine — same interface shape, k inputs instead of 1."""
    k: int
    sensitivity: float = 3.0
    min_samples: int = 30
    decay: float = 0.05
    variance_floor: float = 0.01

    def __post_init__(self):
        self._baseline = MultivariateGaussianBaseline(
            k=self.k,
            sensitivity=self.sensitivity,
            min_samples=self.min_samples,
            decay=self.decay,
            variance_floor=self.variance_floor,
        )

    def process(self, vector: list) -> MultivariateAnomalyResult:
        flagged, d2 = self._baseline.evaluate_and_update(vector)
        # sqrt(d2) is the multivariate analogue of |z| — feed it through
        # the same sigmoid used for the univariate score so scores stay
        # comparable and combinable (e.g. via max()) across detectors.
        score = z_to_score(math.sqrt(d2))
        return MultivariateAnomalyResult(
            raw_vector=list(vector),
            mahalanobis_sq=d2,
            anomaly_score=score,
            is_anomaly=flagged,
        )

    @property
    def baseline(self) -> MultivariateGaussianBaseline:
        return self._baseline
