"""
HW06 Task 1: Checking Password Uniqueness Using Bloom Filter (50 points)

Problem: Create a function to check the uniqueness of passwords using a Bloom
filter. Determine whether a password has been used before WITHOUT storing
the passwords themselves.

Bloom Filter Properties:
- No false negatives: If it says "not present", definitely NOT in set
- Possible false positives: If it says "present", MIGHT be in set
- Space efficient: Uses much less memory than storing actual elements
- Cannot delete: Standard Bloom filters don't support element removal

Algorithm:
1. Initialize bit array of size m (all zeros)
2. Choose k independent hash functions
3. Adding: Set bits at positions hash1(x), hash2(x), ..., hashk(x)
4. Checking: If ALL bits at hash positions are 1 -> "possibly present"
             If ANY bit at hash positions is 0 -> "definitely not present"

Acceptance Criteria:
- BloomFilter class implements add() and membership check (20 pts)
- check_password_uniqueness function works correctly (20 pts)
- Output matches expected format (10 pts)

Optimal Parameters:
- k (hash functions) = (m/n) * ln(2) ≈ 0.693 * (m/n)
- False positive rate p = (1 - e^(-kn/m))^k
- For n=100 elements, m=1000 bits, k=7: ~0.8% false positive rate
"""

import hashlib
from typing import List, Dict
from collections import defaultdict


class BloomFilter:
    """
    Bloom Filter implementation for probabilistic set membership testing.

    A Bloom filter is a space-efficient probabilistic data structure that
    tests whether an element is a member of a set. False positives are
    possible, but false negatives are not.
    """

    def __init__(self, size: int, num_hashes: int):
        """
        Initialize Bloom Filter.

        Args:
            size: Size of the bit array (m)
            num_hashes: Number of hash functions (k)

        Example:
            bloom = BloomFilter(size=1000, num_hashes=3)
        """
        self.size = size
        self.num_hashes = num_hashes
        # TODO: Initialize bit array of given size (all zeros)
        # Option 1: List of integers (simple)
        # self.bit_array = [0] * size
        # Option 2: Use bitarray library for memory efficiency
        self.bit_array = [0] * size

    def _hash(self, item: str, seed: int) -> int:
        """
        Generate hash value for item with given seed.

        Uses MD5 hashing with seed to create k independent hash functions.
        Each seed produces a different hash value for the same item.

        Args:
            item: The string to hash
            seed: Seed value to create different hash functions

        Returns:
            Integer index in range [0, size-1]

        Implementation:
            1. Combine seed and item: f"{seed}:{item}"
            2. Hash using MD5 (or SHA)
            3. Convert hex digest to integer
            4. Take modulo size to get valid index
        """
        # TODO: Create value string combining seed and item
        # TODO: Compute MD5 hash of the encoded value
        # TODO: Convert hex digest to integer
        # TODO: Return index in valid range (0 to size-1)
        value = f"{seed}:{item}"
        hash_value = hashlib.md5(value.encode()).hexdigest()
        return int(hash_value, 16) % self.size

    def add(self, item: str) -> None:
        """
        Add an item to the Bloom filter.

        Sets k bits in the bit array, one for each hash function.
        Once a bit is set, it stays set (no removal support).

        Args:
            item: The item to add (password string)

        Edge cases:
            - Invalid input (not a string): silently ignore
            - Empty string: silently ignore
            - Duplicate add: no effect (idempotent)

        Example:
            bloom.add("password123")
            # Sets bits at hash1("password123"), hash2("password123"), etc.
        """
        # TODO: Validate input - return if not a non-empty string
        # TODO: For each hash function (seed in range(num_hashes)):
        #       - Calculate index = _hash(item, seed)
        #       - Set bit_array[index] = 1
        if not isinstance(item, str) or not item:
            return
        for seed in range(self.num_hashes):
            index = self._hash(item, seed)
            self.bit_array[index] = 1

    def contains(self, item: str) -> bool:
        """
        Check if an item might be in the filter.

        Checks all k hash positions. If ANY bit is 0, item is definitely
        not in the set. If ALL bits are 1, item might be in the set
        (could be a false positive).

        Args:
            item: The item to check

        Returns:
            False = definitely NOT in set (no false negatives)
            True = possibly in set (may be false positive)

        Edge cases:
            - Invalid input (not a string): return False
            - Empty string: return False

        Example:
            bloom.add("password123")
            bloom.contains("password123")  # True (definitely present)
            bloom.contains("unknown")      # Probably False, but could be True
        """
        # TODO: Validate input - return False if not a non-empty string
        # TODO: For each hash function (seed in range(num_hashes)):
        #       - Calculate index = _hash(item, seed)
        #       - If bit_array[index] == 0: return False (definitely not present)
        # TODO: Return True (possibly present - all bits were 1)
        if not isinstance(item, str) or not item:
            return False
        for seed in range(self.num_hashes):
            index = self._hash(item, seed)
            if self.bit_array[index] == 0:
                return False
        return True


def check_password_uniqueness(bloom_filter: BloomFilter,
                               passwords: List[str]) -> Dict[str, str]:
    """
    Check a list of passwords for uniqueness using Bloom filter.

    For each password, checks if it exists in the Bloom filter.
    Returns a status message indicating whether the password is
    unique or already in use.

    Args:
        bloom_filter: BloomFilter instance containing existing passwords
        passwords: List of new passwords to check

    Returns:
        Dictionary mapping each password to its status:
        - "already in use": Password exists in filter (possibly false positive)
        - "unique": Password definitely not in filter
        - "invalid password": Input was not a valid string

    Example:
        bloom = BloomFilter(1000, 3)
        bloom.add("password123")

        results = check_password_uniqueness(bloom, ["password123", "newpass"])
        # {"password123": "already in use", "newpass": "unique"}
    """
    # TODO: Initialize empty results dictionary
    # TODO: For each password in passwords:
    #       - Handle invalid input (not a string, empty)
    #       - Check if bloom_filter.contains(password)
    #       - Set appropriate status message
    # TODO: Return results dictionary
    results = defaultdict(str)
    for password in passwords:
        if not isinstance(password, str) or not password:
            results[password] = "invalid password"
        elif bloom_filter.contains(password):
            results[password] = "already in use"
        else:
            results[password] = "unique"
    return results


# ============== MAIN ==============

if __name__ == "__main__":
    print("=" * 60)
    print("TASK 1: Bloom Filter - Password Uniqueness Checker")
    print("=" * 60)

    # Initialize the Bloom filter
    # size=1000, num_hashes=3 gives reasonable false positive rate
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Add existing passwords
    existing_passwords = ["password123", "admin123", "qwerty123"]
    print("\nAdding existing passwords:")
    for password in existing_passwords:
        print(f"  Adding: {password}")
        bloom.add(password)

    # Check new passwords
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    print(f"\nChecking passwords: {new_passwords_to_check}")

    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Output results
    print("\nResults:")
    for password, status in results.items():
        print(f"  The password '{password}' is {status}.")

    # Expected output:
    # The password 'password123' is already in use.
    # The password 'newpassword' is unique.
    # The password 'admin123' is already in use.
    # The password 'guest' is unique.

    print("\n" + "=" * 60)
    print("Testing Edge Cases:")
    print("=" * 60)

    # Test invalid inputs
    print("\nInvalid input handling:")
    invalid_inputs = [None, 123, "", ["list"]]
    for invalid in invalid_inputs:
        print(f"  check_password_uniqueness(bloom, [{repr(invalid)}])")
        # Uncomment when implemented:
        # result = check_password_uniqueness(bloom, [invalid])
        # print(f"    Result: {result}")

    print("\n" + "=" * 60)
    print("Implementation Status:")
    print("  [TODO] Implement BloomFilter.__init__()")
    print("  [TODO] Implement BloomFilter._hash()")
    print("  [TODO] Implement BloomFilter.add()")
    print("  [TODO] Implement BloomFilter.contains()")
    print("  [TODO] Implement check_password_uniqueness()")
    print("=" * 60)

    # Optional: Test false positive rate
    print("\n" + "=" * 60)
    print("False Positive Rate Test (optional):")
    print("=" * 60)
    print("""
    To test false positive rate:
    1. Add n known passwords to a fresh filter
    2. Check m random strings NOT in the original set
    3. Count false positives (items incorrectly marked as present)
    4. Rate = false_positives / m

    Expected: ~0.8% for size=1000, num_hashes=7, n=100
    """)
