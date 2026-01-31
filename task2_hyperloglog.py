"""
HW06 Task 2: Comparing HyperLogLog with Exact Unique Element Counting (50 points)

Problem: Create a script to compare exact unique element counting (using set)
with approximate counting using HyperLogLog on a log file of IP addresses.

HyperLogLog Properties:
- Uses ~12KB memory regardless of dataset size (with p=14)
- Typical error rate: < 2% for millions of elements
- Much faster than exact counting for large datasets
- Cannot list actual elements (only provides count)

Algorithm Intuition:
- If you hash elements to random binary strings, the maximum number of
  leading zeros observed tells you approximately how many distinct elements
  you've seen: If max leading zeros = k, then estimated count ≈ 2^k
- HyperLogLog improves this by using m buckets (registers) and combining
  estimates using harmonic mean

Acceptance Criteria:
- Data loading method processes log file, ignoring invalid lines (10 pts)
- Exact count function returns correct number of unique IPs (10 pts)
- HyperLogLog shows result with acceptable error (10 pts)
- Results presented in table format (10 pts)
- Code adaptable to large datasets (10 pts)

Note: DO NOT attach log file to LMS submission (too large)
"""

import hashlib
import math
import re
import time
from typing import List, Tuple


class HyperLogLog:
    """
    HyperLogLog implementation for cardinality estimation.

    HyperLogLog is a probabilistic algorithm for counting distinct elements
    using very little memory. It works by:
    1. Hashing elements to get uniform random bits
    2. Using first p bits to select one of 2^p registers
    3. Counting leading zeros in remaining bits
    4. Storing maximum leading zeros seen per register
    5. Combining estimates using harmonic mean
    """

    def __init__(self, precision: int = 14):
        """
        Initialize HyperLogLog counter.

        Args:
            precision: Number of bits for bucket index (p)
                      More precision = more memory but less error
                      p=14 uses 2^14 = 16384 registers (~16KB)
                      Standard error ≈ 1.04 / sqrt(2^p)

        Common precision values:
            p=10: 1024 registers, ~3.25% error
            p=12: 4096 registers, ~1.63% error
            p=14: 16384 registers, ~0.81% error
            p=16: 65536 registers, ~0.41% error
        """
        self.precision = precision
        self.num_registers = 1 << precision  # 2^p
        # TODO: Initialize registers array (all zeros)
        # self.registers = [0] * self.num_registers
        self.registers = [0] * self.num_registers

        # Alpha constant for bias correction (depends on number of registers)
        # TODO: Set alpha based on num_registers
        # if self.num_registers == 16: self.alpha = 0.673
        # elif self.num_registers == 32: self.alpha = 0.697
        # elif self.num_registers == 64: self.alpha = 0.709
        # else: self.alpha = 0.7213 / (1 + 1.079 / self.num_registers)
        if self.num_registers == 16: self.alpha = 0.673
        elif self.num_registers == 32: self.alpha = 0.697
        elif self.num_registers == 64: self.alpha = 0.709
        else: self.alpha = 0.7213 / (1 + 1.079 / self.num_registers)

    def _hash(self, item: str) -> int:
        """
        Generate 64-bit hash for item.

        Uses SHA-256 and takes first 64 bits for good distribution.

        Args:
            item: String to hash

        Returns:
            64-bit integer hash value

        Note: Use cryptographic hash for uniform distribution.
        MD5 or SHA are good choices. Avoid Python's built-in hash().
        """
        # TODO: Encode item and compute SHA-256 hash
        # TODO: Take first 16 hex characters (64 bits)
        # TODO: Convert to integer and return
        value = item.encode()
        hash_value = hashlib.sha256(value).hexdigest()
        return int(hash_value, 16)

    def _get_register_index(self, hash_value: int) -> int:
        """
        Get register index from first p bits of hash.

        Args:
            hash_value: 64-bit hash value

        Returns:
            Register index in range [0, 2^p - 1]

        Implementation:
            Right-shift hash by (64 - precision) bits to get first p bits
        """
        # TODO: Return first p bits of hash as register index
        return hash_value & ((1 << self.precision) - 1)

    def _count_leading_zeros(self, hash_value: int) -> int:
        """
        Count leading zeros in remaining bits after register index.

        The number of leading zeros indicates how "rare" this hash is.
        More leading zeros = higher estimated cardinality.

        Args:
            hash_value: 64-bit hash value

        Returns:
            Number of leading zeros + 1 (position of first 1-bit)

        Implementation:
            1. Mask out the register index bits
            2. Count leading zeros in remaining (64 - p) bits
            3. Return zeros + 1 (we count the position of the first 1)
        """
        # TODO: Mask out register index bits
        remaining_bits = hash_value & ((1 << (64 - self.precision)) - 1)


        # TODO: Handle edge case where remaining is 0
        if remaining_bits == 0:
            return 64 - self.precision
        # TODO: Count leading zeros by checking bits from high to low
        # for i in range(64 - self.precision - 1, -1, -1):
        #     if (remaining_bits >> i) & 1:
        #         break
        #     zeros += 1
        zeros = 0
        for i in range(64 - self.precision - 1, -1, -1):
            if (remaining_bits >> i) & 1:
                break
            zeros += 1

        # TODO: Return zeros + 1
        return zeros + 1

    def add(self, item: str) -> None:
        """
        Add an item to the HyperLogLog counter.

        Updates the appropriate register with the maximum leading zeros
        seen for that register's bucket.

        Args:
            item: String item to add

        Algorithm:
            1. Hash the item to get 64-bit value
            2. Extract register index from first p bits
            3. Count leading zeros in remaining bits
            4. Update register: max(current, leading_zeros)
        """
        # TODO: Validate input
        # TODO: Compute hash
        # TODO: Get register index
        # TODO: Count leading zeros
        # TODO: Update register with max value
        hash_value = self._hash(item)
        register_index = self._get_register_index(hash_value)
        leading_zeros = self._count_leading_zeros(hash_value)
        self.registers[register_index] = max(self.registers[register_index], leading_zeros)

    def count(self) -> int:
        """
        Estimate the cardinality (number of unique elements).

        Uses harmonic mean of register values with bias corrections
        for small and large cardinalities.

        Returns:
            Estimated count of unique elements

        Algorithm:
            1. Calculate raw estimate:
               E = alpha * m^2 / sum(2^(-register[i]) for all i)

            2. Apply small range correction (linear counting):
               If E <= 2.5 * m and there are zero registers:
               E = m * ln(m / zeros)

            3. Apply large range correction:
               If E > 2^32 / 30:
               E = -2^32 * ln(1 - E / 2^32)

            4. Return integer estimate
        """
        # TODO: Calculate sum of 2^(-register) for all registers
        # sum_of_inverses = sum(2 ** (-reg) for reg in self.registers)
        sum_of_inverses = sum(2 ** (-reg) for reg in self.registers)
        # TODO: Calculate raw estimate using harmonic mean
        # raw_estimate = self.alpha * (self.num_registers ** 2) / sum_of_inverses
        raw_estimate = self.alpha * (self.num_registers ** 2) / sum_of_inverses
        # TODO: Apply small range correction if needed
        # if raw_estimate <= 2.5 * self.num_registers:
        #     zeros = self.registers.count(0)
        #     if zeros > 0:
        #         return int(self.num_registers * math.log(self.num_registers / zeros))
        if raw_estimate <= 2.5 * self.num_registers:
            zeros = self.registers.count(0)
            if zeros > 0:
                return int(self.num_registers * math.log(self.num_registers / zeros))
        # TODO: Apply large range correction if needed
        # if raw_estimate > (1 << 32) / 30:
        #     return int(-(1 << 32) * math.log(1 - raw_estimate / (1 << 32)))
        if raw_estimate > (1 << 32) / 30:
            return int(-(1 << 32) * math.log(1 - raw_estimate / (1 << 32)))
        # TODO: Return raw estimate for normal range
        return int(raw_estimate)


def load_ip_addresses(filename: str) -> List[str]:
    """
    Load IP addresses from log file.

    Parses each line looking for valid IPv4 addresses using regex.
    Invalid lines are silently ignored.

    Args:
        filename: Path to the log file

    Returns:
        List of valid IP addresses found in the file

    File format assumed:
        Each line may contain an IP address (e.g., Apache log format)
        IP pattern: four octets separated by dots (0-255.0-255.0-255.0-255)
    """
    # IP pattern regex - matches standard IPv4 format
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ip_addresses = []

    # TODO: Open file with error handling
    # TODO: For each line, extract IP using regex
    # TODO: Optionally validate IP (each octet 0-255)
    # TODO: Add valid IPs to list
    # TODO: Handle FileNotFoundError gracefully
    try:
        with open(filename, 'r', errors='ignore') as f:
            for line in f:
                match = ip_pattern.search(line)
                if match:
                    ip_addresses.append(match.group())
    except FileNotFoundError:
        print(f"File not found: {filename}")
    except Exception as e:
        print(f"Error reading file: {e}")
    return ip_addresses


def is_valid_ip(ip: str) -> bool:
    """
    Validate that IP address has valid octet values.

    Args:
        ip: IP address string (e.g., "192.168.1.1")

    Returns:
        True if all octets are in range 0-255, False otherwise
    """
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    return True


def count_unique_exact(items: List[str]) -> Tuple[int, float]:
    """
    Count unique items exactly using Python set.

    This is the baseline "ground truth" method.

    Args:
        items: List of items to count

    Returns:
        Tuple of (unique_count, execution_time_seconds)
    """
    # TODO: Record start time
    # TODO: Create set from items and get length
    # TODO: Record end time
    # TODO: Return (count, elapsed_time)
    start_time = time.time()
    unique_set = set(items)
    count = len(unique_set)
    end_time = time.time()
    return count, end_time - start_time

def count_unique_hyperloglog(items: List[str], precision: int = 14) -> Tuple[int, float]:
    """
    Count unique items approximately using HyperLogLog.

    Args:
        items: List of items to count
        precision: HyperLogLog precision parameter (default 14)

    Returns:
        Tuple of (estimated_count, execution_time_seconds)
    """
    # TODO: Record start time
    # TODO: Create HyperLogLog with given precision
    # TODO: Add all items
    # TODO: Get count estimate
    # TODO: Record end time
    # TODO: Return (count, elapsed_time)
    start_time = time.time()
    hll = HyperLogLog(precision=precision)
    for item in items:
        hll.add(item)
    count = hll.count()
    end_time = time.time()
    return count, end_time - start_time


def compare_and_display(items: List[str]) -> None:
    """
    Compare exact counting vs HyperLogLog and display results table.

    Displays:
    - Unique element counts from both methods
    - Execution times
    - Error percentage
    - Speed improvement factor

    Args:
        items: List of items to analyze
    """
    print(f"\nTotal items to process: {len(items)}")
    print("\n" + "=" * 60)
    print("Comparison results:")
    print("=" * 60)

    # TODO: Get exact count and time
    # exact_count, exact_time = count_unique_exact(items)
    exact_count, exact_time = count_unique_exact(items)
    # TODO: Get HyperLogLog estimate and time
    # hll_count, hll_time = count_unique_hyperloglog(items)
    hll_count, hll_time = count_unique_hyperloglog(items)
    # TODO: Calculate error percentage
    # error_percent = abs(hll_count - exact_count) / exact_count * 100
    error_percent = abs(hll_count - exact_count) / exact_count * 100
    # TODO: Display formatted table
    # print(f"\n{'Metric':<25} {'Accurate':<15} {'HyperLogLog':<15}")
    # print("-" * 55)
    # print(f"{'Unique elements':<25} {exact_count:<15.0f} {hll_count:<15.0f}")
    # print(f"{'Execution time (sec)':<25} {exact_time:<15.4f} {hll_time:<15.4f}")
    # print(f"{'Error (%)':<25} {'':<15} {error_percent:<15.2f}")
    print(f"\n{'Metric':<25} {'Accurate':<15} {'HyperLogLog':<15}")
    print("-" * 55)
    print(f"{'Unique elements':<25} {exact_count:<15.0f} {hll_count:<15.0f}")
    print(f"{'Execution time (sec)':<25} {exact_time:<15.4f} {hll_time:<15.4f}")
    print(f"{'Error (%)':<25} {'':<15} {error_percent:<15.2f}")
    # TODO: Print analysis summary
    # print(f"\nAnalysis:")
    # print(f"- HyperLogLog is {exact_time/hll_time:.1f}x faster")
    # print(f"- Error rate: {error_percent:.2f}%")
    print(f"\nAnalysis:")
    print(f"- HyperLogLog is {exact_time/hll_time:.1f}x faster")
    print(f"- Error rate: {error_percent:.2f}%")


# ============== MAIN ==============

if __name__ == "__main__":
    print("=" * 60)
    print("TASK 2: HyperLogLog - Unique IP Address Counting")
    print("=" * 60)

    # Option 1: Load from actual log file (uncomment when file available)
    # print("\nLoading IP addresses from log file...")
    # ip_addresses = load_ip_addresses("lms-stage-access.log")

    # Option 2: Generate sample data for testing
    print("\nGenerating sample IP address data for testing...")
    print("(Replace with actual file loading for submission)")

    # Generate 100,000 IP addresses with ~10,000 unique
    ip_addresses = []
    for i in range(100000):
        # Create IP with some repetition to simulate real logs
        octet3 = (i // 100) % 256
        octet4 = i % 100
        ip = f"192.168.{octet3}.{octet4}"
        ip_addresses.append(ip)

    # Run comparison
    if ip_addresses:
        compare_and_display(ip_addresses)
    else:
        print("No IP addresses loaded. Check file path.")

    # Expected output format:
    print("\n" + "=" * 60)
    print("Expected Output Format:")
    print("=" * 60)
    print("""
    Comparison results:

                             Accurate        HyperLogLog
    Unique elements            100000            99852
    Execution time (sec)         0.45             0.10

    Analysis:
    - HyperLogLog is 4.5x faster
    - Error rate: 0.15%
    """)

