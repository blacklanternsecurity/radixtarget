import ipaddress
from contextlib import suppress

from radixtarget.helpers import network_to_bits, merge_subnets
from radixtarget.tree.base import BaseRadixTree, RadixTreeNode, sentinel


class IPRadixTreeNode(RadixTreeNode):
    def defrag(self, parent_datas=None):
        """
        Defrag the node by merging IP networks if they make up a contiguous block.
        """
        cleaned_hosts = set()
        new_hosts = set()

        if parent_datas is None:
            parent_datas = set()
        parent_datas = set(parent_datas)
        if self.data is not sentinel:
            parent_datas.add(self.data)

        # delete children that are duplicates
        for bit, child in list(self.children.items()):
            _cleaned, _new = child.defrag(parent_datas)
            cleaned_hosts.update(_cleaned)
            new_hosts.update(_new)

            # if a child's data matches any parent datas and it doesn't have any children of its own,
            # we can safely delete it
            child_is_safe_to_delete = False
            duplicate_data = child.data in parent_datas
            with suppress(Exception):
                child_has_default_data = child.data == child.host
            child_has_children = child.children
            duplicate_host = parent_datas and child_has_default_data and not child_has_children

            child_is_safe_to_delete = duplicate_data or duplicate_host

            if child_is_safe_to_delete:
                cleaned_hosts.add(child.host)
                del self.children[bit]

        return cleaned_hosts, new_hosts


class IPRadixTree(BaseRadixTree):
    """A radix tree for efficient IP network lookups."""

    node_class = IPRadixTreeNode

    def insert(self, network, data=None):
        """Add an IP network to the tree.

        Args:
            network: IP network to insert (string or ipaddress.IPv4Network/IPv6Network).
            data: Optional data to associate with the network. Defaults to the network itself.
        """
        network = ipaddress.ip_network(network, strict=False)
        if data is None:
            data = network
        node = self.root
        for current_bit in network_to_bits(network):
            if current_bit not in node.children:
                node.children[current_bit] = self.node_class()
            node = node.children[current_bit]
        node.host = network
        node.data = data

    def delete_node(self, query):
        query_network = ipaddress.ip_network(query, strict=False)
        parent_node = self.root
        network_bits = list(network_to_bits(query_network))
        if network_bits:
            for bit in network_bits[:-1]:
                try:
                    parent_node = parent_node.children[bit]
                except KeyError:
                    raise KeyError(f'IP "{query}" not found')
        else:
            # clear out host+data without deleting children
            self.root.host = None
            self.root.data = sentinel
            return

        node_index = network_bits[-1]
        try:
            old_node = parent_node.children[node_index]
        except KeyError:
            raise KeyError(f'IP "{query}" not found')
        if old_node.host is None:
            raise KeyError(f"Cannot delete node with no host: {old_node.host}")
        if old_node.children:
            # replace the node with a blank/passthrough
            new_node = self.node_class()
            new_node.children = old_node.children
            parent_node.children[node_index] = new_node
        else:
            del parent_node.children[node_index]

    def get_node(self, query, raise_error=False):
        """Find the most specific matching entry for a given IP address or network.

        Args:
            query: IP address or network to search for (string or ipaddress object).
            raise_error: If True, raise KeyError when no match is found. Defaults to False.

        Returns:
            The node associated with the most specific matching network, or None if no match.
        """
        query_network = ipaddress.ip_network(query, strict=False)

        node = self.root
        matched_node = sentinel
        network_bits = list(network_to_bits(query_network))

        # handle 0.0.0.0/0 and ::/0
        if node.host and query_network.network_address in node.host:
            matched_node = node

        for bit in network_bits:
            if bit in node.children:
                node = node.children[bit]
                if node.host and node.host.prefixlen <= query_network.prefixlen:
                    if query_network.network_address in node.host:
                        matched_node = node
            else:
                break

        if matched_node is sentinel:
            if raise_error:
                raise KeyError(f'IP "{query}" not found')
            return None
        return matched_node

    def clean_duplicates(self):
        cleaned_hosts = set()
        new_hosts = set()

        # make a sorted list of all hosts with their nodes
        nodes_by_host = self.root.nodes_by_host
        nodes_by_host_sorted = sorted(nodes_by_host.items(), key=lambda x: (x[0].prefixlen, x[0].network_address))
        if len(nodes_by_host_sorted) > 1:
            for i in range(len(nodes_by_host_sorted) - 1):
                node1_host, node1 = nodes_by_host_sorted[i]
                node2_host, node2 = nodes_by_host_sorted[i + 1]

                try:
                    new_subnet = merge_subnets(node1_host, node2_host)
                except ValueError:
                    continue

                # see if there's already a node matching the summarized network
                existing_node = nodes_by_host.get(new_subnet, None)
                existing_node_data = getattr(existing_node, "data", sentinel)

                matching_data = False
                with suppress(Exception):
                    if existing_node is None:
                        matching_data = node1.data == node2.data
                    else:
                        matching_data = existing_node_data == node1.data == node2.data

                default_data = False
                with suppress(Exception):
                    if existing_node is None:
                        default_data = node1.data == node1.host and node2.data == node2.host
                    else:
                        default_data = (
                            existing_node.data == existing_node.host
                            and node1.data == node1.host
                            and node2.data == node2.host
                        )

                if matching_data or default_data:
                    # add new node
                    self.insert(new_subnet, data=(None if default_data else node1.data))
                    new_hosts.add(new_subnet)

                    # delete old nodes
                    self.delete_node(node1_host)
                    self.delete_node(node2_host)
                    cleaned_hosts.add(node1_host)
                    cleaned_hosts.add(node2_host)

        return cleaned_hosts, new_hosts

    def defrag(self):
        cleaned_hosts = set()
        new_hosts = set()

        # defrag until no more changes
        while 1:
            pruned = self.prune()
            _dup_cleaned, _dup_new = self.clean_duplicates()
            pruned += self.prune()
            _frag_cleaned, _frag_new = self.root.defrag()
            pruned += self.prune()
            if pruned == 0 and (not _dup_cleaned) and (not _dup_new) and (not _frag_cleaned) and (not _frag_new):
                break
            cleaned_hosts.update(_dup_cleaned)
            cleaned_hosts.update(_frag_cleaned)
            new_hosts.update(_dup_new)
            new_hosts.update(_frag_new)

        # remove intermediate hosts
        intermediate_hosts = new_hosts.intersection(cleaned_hosts)
        new_hosts.difference_update(intermediate_hosts)
        cleaned_hosts.difference_update(intermediate_hosts)
        return cleaned_hosts, new_hosts

    def prune(self):
        return self.root.prune()
