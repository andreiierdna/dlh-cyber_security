#!/usr/bin/env python3
"""Query and display all DNS record types using the dnspython library."""
import dns.resolver


def query_dns_records(domain_name):
    """Query multiple DNS record types for a given domain.

    Args:
        domain_name (str): The domain name to query.

    Returns:
        dict: A dictionary containing DNS resolver answers organized
            by record type. Format:
            {'A': answers_object, 'AAAA': answers_object, ...}
            Only includes record types that were successfully queried.
            Returns an empty dictionary if the domain cannot be resolved.
    """
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    results = {}

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain_name, record_type)
            results[record_type] = answers
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            return {}
        except dns.resolver.NoNameservers:
            continue
        except Exception:
            continue

    return results


if __name__ == "__main__":
    import sys
    domain_name = sys.argv[1]
    results = query_dns_records(domain_name)
    for record_type, response_text in results.items():
        print(f"\n{record_type} Records:")
        print(response_text.response.to_text())
    print("\nResults dictionary:", results)
