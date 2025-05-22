import hashlib
import secrets
import sys
import os
import argparse
from typing import Dict, List, Tuple, Optional
from enum import Enum, auto
import json
import signal

class HashAlgorithm(Enum):
    """Supported hash algorithms with their security levels"""
    MD5 = ('md5', 'weak', 'Cryptographically broken')
    SHA1 = ('sha1', 'weak', 'Cryptographically broken')
    SHA224 = ('sha224', 'moderate', 'Small output size')
    SHA256 = ('sha256', 'strong', None)
    SHA384 = ('sha384', 'strong', None)
    SHA512 = ('sha512', 'strong', None)
    SHA3_224 = ('sha3_224', 'moderate', 'Small output size')
    SHA3_256 = ('sha3_256', 'strong', None)
    SHA3_384 = ('sha3_384', 'strong', None)
    SHA3_512 = ('sha3_512', 'strong', None)
    BLAKE2B = ('blake2b', 'strong', None)
    BLAKE2S = ('blake2s', 'strong', None)

    def __init__(self, algorithm_name: str, security_level: str, security_note: Optional[str]):
        self.algorithm_name = algorithm_name
        self.security_level = security_level
        self.security_note = security_note

class ChecksumMode(Enum):
    """Operation modes for the checksum utility"""
    GENERATE = auto()
    VALIDATE = auto()
    COMPARE = auto()

class ChecksumError(Exception):
    """Base exception for all checksum-related errors"""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class FileOperationError(ChecksumError):
    """Raised for file-related errors"""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class HashComputationError(ChecksumError):
    """Raised when hash computation fails"""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class ValidationError(ChecksumError):
    """Raised when checksum validation fails"""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class SecurityWarning(ChecksumError):
    """Raised when using potentially insecure algorithms"""
    def __init__(self, message, error_code = None):
        super().__init__(message, error_code)

class ChecksumWizard:
    """Industrial-grade file checksum utility with comprehensive features"""
    
    CHUNK_SIZE = 65536  # 64KB chunks for memory-efficient hashing
    
    def __init__(self, file_path: str):
        """
        Initialize checksum wizard with target file
        
        Args:
            file_path: Path to the file to process
            
        Raises:
            FileOperationError: If file cannot be accessed
        """
        self.file_path = file_path
        self.file_size = 0
        self._validate_file()
    
    def _validate_file(self) -> None:
        """Validate that the file exists and is accessible"""
        try:
            if not os.path.exists(self.file_path):
                raise FileOperationError(f"File not found: {self.file_path}")
            if not os.path.isfile(self.file_path):
                raise FileOperationError(f"Path is not a file: {self.file_path}")
            if not os.access(self.file_path, os.R_OK):
                raise FileOperationError(f"Permission denied: {self.file_path}")
            
            self.file_size = os.path.getsize(self.file_path)
            if self.file_size == 0:
                raise FileOperationError(f"File is empty: {self.file_path}")
                
        except OSError as e:
            raise FileOperationError(f"File validation failed: {str(e)}")
    
    def compute_checksums(self, algorithms: List[HashAlgorithm]) -> Dict[str, str]:
        """
        Compute checksums for the file using specified algorithms
        
        Args:
            algorithms: List of HashAlgorithm enum values
            
        Returns:
            Dictionary mapping algorithm names to their checksums
            
        Raises:
            HashComputationError: If checksum computation fails
        """
        results = {}
        
        try:
            # Initialize all hash objects
            hash_objects = {
                alg.algorithm_name: getattr(hashlib, alg.algorithm_name)()
                for alg in algorithms
                if hasattr(hashlib, alg.algorithm_name)
            }
            
            # Read file once and update all hashes
            with open(self.file_path, 'rb') as f:
                while chunk := f.read(self.CHUNK_SIZE):
                    for hash_obj in hash_objects.values():
                        hash_obj.update(chunk)
            
            # Get hexdigests for all algorithms
            for alg in algorithms:
                if alg.algorithm_name in hash_objects:
                    results[alg.algorithm_name] = hash_objects[alg.algorithm_name].hexdigest()
                else:
                    raise HashComputationError(f"Algorithm not available: {alg.algorithm_name}")
            
            return results
            
        except IOError as e:
            raise FileOperationError(f"Failed to read file: {str(e)}")
        except Exception as e:
            raise HashComputationError(f"Checksum computation failed: {str(e)}")
    
    def validate_checksum(
        self,
        algorithm: HashAlgorithm,
        expected_checksum: str,
        warn_insecure: bool = True
    ) -> bool:
        """
        Validate file against an expected checksum
        
        Args:
            algorithm: HashAlgorithm to use
            expected_checksum: Expected checksum value
            warn_insecure: Whether to warn about insecure algorithms
            
        Returns:
            bool: True if checksum matches, False otherwise
            
        Raises:
            ValidationError: If validation fails
            SecurityWarning: If using insecure algorithm with warn_insecure=True
        """
        if warn_insecure and algorithm.security_level == 'weak':
            raise SecurityWarning(
                f"Algorithm {algorithm.algorithm_name} is not secure: {algorithm.security_note}"
            )
        
        try:
            computed = self.compute_checksums([algorithm])[algorithm.algorithm_name]
            if not secrets.compare_digest(computed.lower(), expected_checksum.lower()):
                raise ValidationError(
                    f"Checksum mismatch for {algorithm.algorithm_name}\n"
                    f"Expected: {expected_checksum}\n"
                    f"Actual:   {computed}"
                )
            return True
        except ChecksumError:
            raise
        except Exception as e:
            raise ValidationError(f"Validation failed: {str(e)}")
    
    def compare_files(self, other_file: str, algorithm: HashAlgorithm) -> bool:
        """
        Compare this file with another file using the specified algorithm
        
        Args:
            other_file: Path to the other file
            algorithm: HashAlgorithm to use
            
        Returns:
            bool: True if files have identical checksums, False otherwise
            
        Raises:
            FileOperationError: If other file cannot be accessed
            HashComputationError: If checksum computation fails
        """
        try:
            other_wizard = ChecksumWizard(other_file)
            our_checksum = self.compute_checksums([algorithm])[algorithm.algorithm_name]
            their_checksum = other_wizard.compute_checksums([algorithm])[algorithm.algorithm_name]
            
            return secrets.compare_digest(our_checksum, their_checksum)
        except ChecksumError:
            raise
        except Exception as e:
            raise HashComputationError(f"File comparison failed: {str(e)}")


class ChecksumCLI:
    """Command-line interface for the checksum utility"""
    
    @staticmethod
    def _signal_handler(signum, frame):
        """Handle interrupt signals gracefully"""
        raise KeyboardInterrupt("Operation cancelled by user")
    
    @staticmethod
    def run():
        """Run the checksum utility based on command-line arguments"""
        signal.signal(signal.SIGINT, ChecksumCLI._signal_handler)
        signal.signal(signal.SIGTERM, ChecksumCLI._signal_handler)
        
        parser = argparse.ArgumentParser(
            description='Industrial-Grade File Checksum Utility',
            epilog='Example: checksum.py generate file.txt --algorithms sha256 sha512 --output checksums.json'
        )
        
        # Required arguments
        parser.add_argument(
            'mode',
            choices=['generate', 'validate', 'compare'],
            help='Operation mode: generate checksums, validate against a checksum, or compare two files'
        )
        parser.add_argument(
            'file',
            help='Path to the input file (for compare mode, this is the first file)'
        )
        
        # Mode-specific arguments
        parser.add_argument(
            '--checksum',
            help='Expected checksum for validation mode'
        )
        parser.add_argument(
            '--other-file',
            help='Second file for comparison mode'
        )
        parser.add_argument(
            '--algorithm',
            choices=[alg.algorithm_name for alg in HashAlgorithm],
            default='sha256',
            help='Hash algorithm to use (default: sha256)'
        )
        
        # Optional arguments
        parser.add_argument(
            '--algorithms',
            nargs='+',
            choices=[alg.algorithm_name for alg in HashAlgorithm],
            default=['sha256', 'sha512'],
            help='Algorithms to use for generation (default: sha256 sha512)'
        )
        parser.add_argument(
            '--output',
            help='Output file to save results (JSON format)'
        )
        parser.add_argument(
            '--no-warn',
            action='store_true',
            help='Suppress security warnings about weak algorithms'
        )
        
        args = parser.parse_args()
        
        try:
            # Convert algorithm strings to enum values
            def get_algorithm(name: str) -> HashAlgorithm:
                for alg in HashAlgorithm:
                    if alg.algorithm_name == name:
                        return alg
                raise ValueError(f"Unknown algorithm: {name}")
            
            main_algorithm = get_algorithm(args.algorithm)
            algorithm_list = [get_algorithm(alg) for alg in args.algorithms]
            
            # Execute based on mode
            wizard = ChecksumWizard(args.file)
            result = {}
            
            if args.mode == 'generate':
                checksums = wizard.compute_checksums(algorithm_list)
                result = {
                    'file': args.file,
                    'checksums': checksums,
                    'metadata': {
                        'size': wizard.file_size,
                        'algorithms': args.algorithms
                    }
                }
                print("Generated checksums:")
                for alg, checksum in checksums.items():
                    print(f"{alg}: {checksum}")
            
            elif args.mode == 'validate':
                if not args.checksum:
                    parser.error("--checksum is required for validate mode")
                
                try:
                    wizard.validate_checksum(main_algorithm, args.checksum, not args.no_warn)
                    result = {
                        'status': 'valid',
                        'algorithm': args.algorithm,
                        'file': args.file,
                        'expected': args.checksum
                    }
                    print("Checksum validation successful")
                except ValidationError as e:
                    result = {
                        'status': 'invalid',
                        'algorithm': args.algorithm,
                        'file': args.file,
                        'expected': args.checksum,
                        'error': str(e)
                    }
                    print(f"Checksum validation failed: {str(e)}")
                    sys.exit(1)
            
            elif args.mode == 'compare':
                if not args.other_file:
                    parser.error("--other-file is required for compare mode")
                
                try:
                    match = wizard.compare_files(args.other_file, main_algorithm)
                    result = {
                        'status': 'match' if match else 'mismatch',
                        'algorithm': args.algorithm,
                        'file1': args.file,
                        'file2': args.other_file
                    }
                    print(f"Files {'match' if match else 'do not match'} using {args.algorithm}")
                    if not match:
                        sys.exit(1)
                except ChecksumError as e:
                    result = {
                        'status': 'error',
                        'algorithm': args.algorithm,
                        'file1': args.file,
                        'file2': args.other_file,
                        'error': str(e)
                    }
                    print(f"Comparison failed: {str(e)}")
                    sys.exit(1)
            
            # Save results if requested
            if args.output:
                try:
                    with open(args.output, 'w') as f:
                        json.dump(result, f, indent=2)
                    print(f"Results saved to {args.output}")
                except IOError as e:
                    print(f"Failed to save results: {str(e)}", file=sys.stderr)
                    sys.exit(1)
        
        except KeyboardInterrupt:
            print("\nOperation cancelled by user", file=sys.stderr)
            sys.exit(1)
        except ChecksumError as e:
            print(f"Error: {str(e)}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error: {str(e)}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    ChecksumCLI.run()
