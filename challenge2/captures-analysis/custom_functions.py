#
#                  Politecnico di Milano
#
#         Student: Caravano Andrea, Cantele Alberto
#            A.Y.: 2024/2025
#
#   Last modified: 05/04/2025
#
#     Description: Internet of Things: Challenge n. 2
#                  Packet captures analysis: custom functions
#

import pyshark
import nest_asyncio
import re

# needed for PyShark, allows for asynchronous nested loops, as they are needed for packet analysis
nest_asyncio.apply()

#### DNS Constants declaration (response types scalar values) ####
DNS_IPv4_TYPE = 1
DNS_IPv6_TYPE = 28
#### MQTT Constants declaration (message types scalar values) ####
# Message types
MQTT_CONNECT = 1
MQTT_CONNECT_ACK = 2
MQTT_SUBSCRIBE = 8
MQTT_SUBSCRIBE_ACK = 9

#### PCAP FILE URI ####
PCAP_URI = "challenge2.pcapng"


#### GENERIC PACKET SOCKET IDENTIFIERS ####
def get_socket_details(p):
    # Extracts IPv4 or IPv6 source and destination addresses
    ip_couple = None
    if hasattr(p, 'ip'):
        ip_couple = [p.ip.src, p.ip.dst]
    elif hasattr(p, 'ipv6'):
        ip_couple = [p.ipv6.src, p.ipv6.dst]
    # Extracts TCP or UDP source and destination port
    transport_couple = None
    if hasattr(p, 'tcp'):
        transport_couple = [p.tcp.srcport, p.tcp.dstport]
    elif hasattr(p, 'udp'):
        transport_couple = [p.udp.srcport, p.udp.dstport]
    # The result will be a complete socket
    return ip_couple + transport_couple


#### DNS ADDRESS RESOLUTION ####
def get_addresses(symbolic_name):
    # Filters DNS responses pertaining to the INternet class and providing an answer containing an IPv4 or IPv6 address, matching the symbolic name given as a parameter
    address_capture = pyshark.FileCapture(
        PCAP_URI,
        display_filter="dns and dns.flags.response == 1 and dns.qry.name == \"{}\" and dns.resp.class == 0x0001 and (dns.resp.type == {} or dns.resp.type == {})"
        .format(symbolic_name,
                DNS_IPv4_TYPE,
                DNS_IPv6_TYPE
                ))

    # A hash-based unique data structure, that will contain all different addresses derived from DNS responses
    addresses = set()
    malformed_packets = 0
    for packet in address_capture:
        try:
            dns_layer = packet.dns
            # IPv4 addresses
            if hasattr(dns_layer, 'a'):
                for addr in dns_layer.a.all_fields:
                    addresses.add(addr.showname_value)
            # IPv6 addresses
            if hasattr(dns_layer, 'aaaa'):
                for addr in dns_layer.aaaa.all_fields:
                    addresses.add(addr.showname_value)
        except:
            # A malformed packet has been found and computation needed to be stopped, counting it
            malformed_packets += 1

    # print("First sub-computation ended, found %d malformed packets." % malformed_packets)

    # Capture object is freed to allow easier usage of successive sub-computations
    address_capture.close()
    address_capture.clear()

    return addresses


#### MQTT CONNECT ACK VERIFICATION ####
def check_connect_ack(p):
    # Assumption: if IPv6 is not used, IPv4 is automatically assumed!
    ipv6 = hasattr(p, 'ipv6')
    packet_filter = "mqtt and mqtt.msgtype == {} and ip.src == {} and ip.dst == {} and tcp.srcport == {} and tcp.dstport == {} and tcp.ack == {} and frame.number > {}"
    if ipv6:
        packet_filter = packet_filter.replace('ip.', 'ipv6.')

    # Filters the corresponding Connect ACK responses coming from the opposite socket couple, naturally, having also a frame number greater than the Connect one, logically
    connect_ack_search = pyshark.FileCapture(
        PCAP_URI,
        display_filter=packet_filter
        .format(MQTT_CONNECT_ACK,
                p.ip.dst if not ipv6 else p.ipv6.dst,
                p.ip.src if not ipv6 else p.ipv6.src,
                p.tcp.dstport,
                p.tcp.srcport,
                p.tcp.nxtseq,
                p.frame_info.number)
    )

    # Capture object is freed to allow easier usage of successive sub-computations
    connect_ack_search.close()
    connect_ack_search.clear()

    return len(list(connect_ack_search)) >= 1


#### MQTT CLIENT ID ####
def search_clientid(p):
    # Assumption: if IPv6 is not used, IPv4 is automatically assumed!
    ipv6 = hasattr(p, 'ipv6')
    packet_filter = "mqtt and mqtt.msgtype == {} and ip.src == {} and ip.dst == {} and tcp.srcport == {} and tcp.dstport == {} and frame.number < {}"
    if ipv6:
        packet_filter = packet_filter.replace('ip.', 'ipv6.')

    # Filters MQTT Connect packets coming from a client, obviously connected before the given packet p, having the same socket identifiers
    connect_search = pyshark.FileCapture(
        PCAP_URI,
        display_filter=packet_filter
        .format(
            MQTT_CONNECT,
            p.ip.src if not ipv6 else p.ipv6.src,
            p.ip.dst if not ipv6 else p.ipv6.dst,
            p.tcp.srcport,
            p.tcp.dstport,
            p.frame_info.number
        )
    )
    # Capture object is freed to allow easier usage of successive sub-computations
    connect_search.close()
    connect_search.clear()

    cid = None
    malformed_packets = 0
    for conn in connect_search:
        try:
            # Client ID has been correctly identified, and we can distinguish clients using their IDs now!
            if check_connect_ack(conn):
                cid = conn.mqtt.clientid
        except:
            # A malformed packet has been found and computation needed to be stopped, counting it
            malformed_packets += 1

    # print("First sub-computation ended, found %d malformed packets." % malformed_packets)

    return cid


#### MQTT SUBSCRIPTIONS DERIVATION ####
# Assumption: no unsubscribe message is never sent by any client
# This is proved by the pcap file, not having any packet carrying mqtt.msgtype == 10 (UNSUBSCRIBE)
# Derivation can, however, be extended to this case, parsing the unsubscribe topic list accordingly, matching it to the unsubscribe ack and its response codes
def compute_subscriptions(p, lower_bound):
    # Assumption: if IPv6 is not used, IPv4 is automatically assumed!
    ipv6 = hasattr(p, 'ipv6')
    packet_filter = "mqtt and mqtt.msgtype == {} and ip.src == {} and ip.dst == {} and tcp.srcport == {} and tcp.dstport == {} and frame.number > {} and frame.number < {}"
    if ipv6:
        packet_filter = packet_filter.replace('ip.', 'ipv6.')

    # Filters MQTT Subscribe packets, having the opposite socket couple with respect to the provided packet, since we are receiving in input a Publish packet
    # The meaningful direction is, in fact, the one coming from the broker to the MQTT subscriber
    # Its position will naturally be preceding the Publish packet and following the Last Will message embedded in the Connect one, as shown
    subscribes = pyshark.FileCapture(
        PCAP_URI,
        display_filter=packet_filter
        .format(MQTT_SUBSCRIBE,
                p.ip.dst if not ipv6 else p.ipv6.dst,
                p.ip.src if not ipv6 else p.ipv6.src,
                p.tcp.dstport,
                p.tcp.srcport,
                lower_bound,
                p.frame_info.number)
    )

    packet_filter = "mqtt and mqtt.msgtype == {} and ip.src == {} and ip.dst == {} and tcp.srcport == {} and tcp.dstport == {} and tcp.ack == {} and mqtt.msgid == {} and frame.number > {} and frame.number < {}"
    if ipv6:
        packet_filter = packet_filter.replace('ip.', 'ipv6.')

    # A hash-based unique data structure, that will contain all different subscription strings derived from the Subscribe messages
    subs = set()
    malformed_packets = 0
    for packet in subscribes:
        try:
            # Matches corresponding Subscribe ACKs, coming from the opposite socket couple, naturally, having also a frame number greater than the Subscribe one and smaller than the Publish one, logically
            subscribe_acks = pyshark.FileCapture(
                PCAP_URI,
                display_filter=packet_filter
                .format(MQTT_SUBSCRIBE_ACK,
                        p.ip.src if not ipv6 else p.ipv6.src,
                        p.ip.dst if not ipv6 else p.ipv6.dst,
                        p.tcp.srcport,
                        p.tcp.dstport,
                        packet.tcp.nxtseq,
                        packet.mqtt.msgid,
                        packet.frame_info.number,
                        p.frame_info.number)
            )
            assert len(list(subscribe_acks)) >= 1
            # Then it means the subscription has been correctly acked, so we can register it among the valid subscriptions

            # Capture object is freed to allow easier usage of successive sub-computations
            subscribe_acks.close()
            subscribe_acks.clear()

            topic = packet.mqtt.topic
            subs.add(topic)
        except:
            # A malformed packet has been found and computation needed to be stopped, counting it
            malformed_packets += 1

    # print("First sub-computation ended, found %d malformed packets." % malformed_packets)

    # Capture object is freed to allow easier usage of successive sub-computations
    subscribes.close()
    subscribes.clear()

    return subs


#### MQTT TOPIC MATCHING (manual conversion to regex matching) ####
def mqtt_topic_matches(subscription_pattern, topic_to_check):
    # receives a subscription pattern (one of the derived subscriptions from the Subscribe messages) and a topic to check for (that is, matching against)
    # obviously if the pattern contains only the wildcard, anything matches
    if subscription_pattern == '#':
        return True

    # MQTT topic matching can be easily modeled using regular expressions
    regex_pattern = re.escape(subscription_pattern)

    # with + matching one level (so, between level separators, /)
    regex_pattern = regex_pattern.replace('\\+', '([^/]+)')

    # the wildcard (#) is expected to appear only at the end and can be replaced with a Kleene star (so, anything matches from that point on)
    if regex_pattern.endswith('\\#'):
        regex_pattern = regex_pattern[:-2] + '(.*)'
    # Protocol violation: wildcard is used in the interest declaration body
    elif '\\#' in regex_pattern:
        return False

    # Expression is now complete: let's match it
    return bool(re.match('^' + regex_pattern + '$', topic_to_check))
