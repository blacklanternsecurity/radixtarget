import ipaddress
from ._radixtarget import PyRadixTarget


class RadixTarget:
    """
    A class representing a target. Can contain an unlimited number of hosts, IPs, or IP ranges.
    
    This class uses the Rust-based PyRadixTarget as a backend and adds Python-based data storage.
    """
    
    def __init__(self, *targets, strict_scope=False, acl_mode=False):
        """
        Initialize a RadixTarget object.
        
        Args:
            *targets: One or more targets (e.g., domain names, IP ranges) to be included in this Target.
            strict_scope (bool): Whether to consider subdomains of target domains in-scope
            acl_mode (bool): ACL mode - reject hosts already contained and delete children when adding parents
        """
        # Initialize the Rust backend
        self._rust_target = PyRadixTarget(strict_scope=strict_scope, acl_mode=acl_mode)
        
        # Python-based data storage: canonical_value -> data
        self._data = {}
        
        # Add any targets passed to constructor
        if targets:
            for target in targets:
                self.add(target)
    
    def insert(self, value, data=None):
        """
        Insert a value with optional data.
        
        Args:
            value (str): The value to insert
            data: Optional data to associate with the value (defaults to the canonical form)
            
        Returns:
            str or None: Canonical form of the inserted value, or None if rejected by ACL mode
        """
        # Use Rust backend to insert and get canonical form
        canonical_value = self._rust_target.insert(value)
        
        if canonical_value is not None:
            # Store data using canonical value as key - default to the canonical form itself
            data_to_store = data if data is not None else canonical_value
            self._data[canonical_value] = data_to_store
        
        return canonical_value
    
    def add(self, value, data=None):
        """Alias for insert()"""
        return self.insert(value, data=data)
    
    def put(self, value, data=None):
        """Alias for insert()"""
        return self.insert(value, data=data)
    
    def get(self, value):
        """
        Get the data associated with a value.
        
        Args:
            value (str): The value to look up
            
        Returns:
            The data associated with the value, or None if not found
        """
        canonical_value = self._rust_target.get(value)
        if canonical_value is not None:
            return self._data.get(canonical_value)
        return None
    
    def search(self, value):
        """Alias for get()"""
        return self.get(value)
    
    def delete(self, value):
        """
        Delete a value and its associated data.
        
        Args:
            value (str): The value to delete
            
        Returns:
            bool: True if the value was deleted, False otherwise
        """
        # Get canonical value before deleting to remove associated data
        canonical_value = self._rust_target.get(value)
        if canonical_value is not None:
            self._data.pop(canonical_value, None)
        
        return self._rust_target.delete(value)
    
    def __contains__(self, value):
        """Check if a value is contained in the target"""
        # If "value" is another RadixTarget, check if all its entries are in self
        if isinstance(value, RadixTarget):
            return self._rust_target.contains_target(value._rust_target)
        else:
            return self._rust_target.contains(value)
    
    def __len__(self):
        """Return the number of entries in the target"""
        return self._rust_target.__len__()
    
    def __bool__(self):
        """Return True if the target is not empty"""
        return self._rust_target.__bool__()
    
    def __str__(self):
        """Return string representation of the target"""
        return self._rust_target.__str__()
    
    def __repr__(self):
        """Return detailed representation of the target"""
        return self._rust_target.__repr__()
    
    def __eq__(self, other):
        """Check equality with another target"""
        if isinstance(other, RadixTarget):
            return self._rust_target.__eq__(other._rust_target)
        return False
    
    def __hash__(self):
        """Return hash of the target"""
        return self._rust_target.__hash__()
