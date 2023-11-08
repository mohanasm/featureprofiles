# TE-2.3.1: Primary encap unviable but backup encap viable for single tunnel

## Summary

Tests that if the primary NHG for an encap tunnel is unviable, then the traffic for that tunnel is re-encaped into its specified backup tunnel. 

## Procedure

*   Topology:  

      DUT port-1 <------> port-1 ATE

      DUT port-2 <------> port-2 ATE (primary tunnel egress port) 

      DUT port-3 <------> port-3 ATE (primary tunnel egress port) 

      DUT port-4 <------> port-4 ATE (primary tunnel egress port) 

      DUT port-5 <------> port-5 ATE (backup tunnel egress port) 

      DUT port-6 <------> port-6 ATE (primary tunnel egress port) 

      DUT port-7 <------> port-7 ATE (backup tunnel egress port) 

      DUT port-8 <------> port-8 ATE (static route in default VRF egress port) 

 

Apply vrf_selectioin_policy_c to DUT port-1 

 

Using gRIBI, install the following gRIBI AFTs, and validate the specified behavior. 

 

     

 

 

 

IPv4Entry {138.0.11.0/24 (ENCAP_TE_VRF_A)} -> NHG#10 (DEFAULT VRF) -> { 

        {NH#201, DEFAULT VRF, weight:1}, 

        {NH#202, DEFAULT VRF, weight:3}, 

} 

NH#201 -> { 

      encapsulate_header: OPENCONFIGAFTTYPESENCAPSULATIONHEADERTYPE_IPV4 

      ip_in_ip { 

        dst_ip: "203.0.113.1" 

        src_ip: "ipv4_outer_src_111" 

      } 

      network_instance: "TE_VRF_111" 

} 

NH#202 -> { 

      encapsulate_header: OPENCONFIGAFTTYPESENCAPSULATIONHEADERTYPE_IPV4 

      ip_in_ip { 

        dst_ip: "203.10.113.2" 

        src_ip: "ipv4_outer_src_111" 

      } 

      network_instance: "TE_VRF_111" 

} 

 

 

IPv4Entry {203.0.113.1/32 (TE_VRF_111)} -> NHG#1 (DEFAULT VRF) -> { 

        {NH#1, DEFAULT VRF, weight:1,ip_address=192.0.2.101}, 

        {NH#2, DEFAULT VRF, weight:3,ip_address=192.0.2.102}, 

        backup_next_hop_group: 8 # re-encap to 203.0.113.100 

} 

IPv4Entry {192.0.2.101/32 (DEFAULT VRF)} -> NHG#2 (DEFAULT VRF) -> { 

        {NH#10, DEFAULT VRF, weight:1,mac_address:magic_mac, interface-ref:dut-port-2-interface}, 

        {NH#11, DEFAULT VRF, weight:3,mac_address:magic_mac, interface-ref:dut-port-3-interface}, 

} 

IPv4Entry {192.0.2.102/32 (DEFAUlT VRF)} -> NHG#3 (DEFAULT VRF) -> { 

        {NH#100, DEFAULT VRF, weight:2,mac_address:magic_mac, interface-ref:dut-port-4-interface}, 

} 

 

NHG#8 (Default VRF) { 

        {NH#1000, DEFAULT VRF} 

} 

NH#1000 -> { 

      encapsulate_header: OPENCONFIGAFTTYPESENCAPSULATIONHEADERTYPE_IPV4 

      ip_in_ip { 

        dst_ip: "203.0.113.100" 

        src_ip: "ipv4_outer_src_222" 

      } 

      network_instance: "TE_VRF_222" 

} 

 

IPv4Entry {203.0.113.100/32 (TE_VRF_222)} -> NHG#7 (DEFAULT VRF) -> { 

        {NH#3, DEFAULT VRF, weight:1,ip_address=192.0.2.103}, 

} 

IPv4Entry {192.0.2.103/32 (DEFAULT VRF)} -> NHG#8 (DEFAULT VRF) -> { 

        {NH#12, DEFAULT VRF, weight:1,mac_address:magic_mac, interface-ref:dut-port-5-interface}, 

} 

 

# 203.10.113.2 is the tunnel IP address. Note that the NHG#4 

# is different than NHG#1. 

 

IPv4Entry {203.10.113.2/32 (TE_VRF_111)} -> NHG#4 (DEFAULT VRF) -> { 

        {NH#3, DEFAULT VRF, weight:1,ip_address=192.0.2.104}, 

 

        backup_next_hop_group: 9 # re-encap to 203.10.113.101 

} 

IPv4Entry {192.0.2.104/32 (DEFAULT VRF)} -> NHG#5 (DEFAULT VRF) -> { 

        {NH#12, DEFAULT VRF, weight:1,mac_address:magic_mac, interface-ref:dut-port-6-interface}, 

} 

NHG#9 (Default VRF) { 

        {NH#1001, DEFAULT VRF} 

} 

NH#1001 -> { 

      encapsulate_header: OPENCONFIGAFTTYPESENCAPSULATIONHEADERTYPE_IPV4 

      ip_in_ip { 

        dst_ip: "203.0.113.101" 

        src_ip: "ipv4_outer_src_222" 

      } 

      network_instance: "TE_VRF_222" 

} 

IPv4Entry {203.0.113.101/32 (TE_VRF_222)} -> NHG#9 (DEFAULT VRF) -> { 

        {NH#3, DEFAULT VRF, weight:1,ip_address=192.0.2.103}, 

} 

IPv4Entry {192.0.2.103/32 (DEFAULT VRF)} -> NHG#10 (DEFAULT VRF) -> { 

        {NH#12, DEFAULT VRF, weight:1,mac_address:magic_mac, interface-ref:dut-port-7-interface}, 

} 

 

    Install a BGP route resolved by ISIS in default VRF to route 138.0.11.8 traffic out of DUT port-8. 

    Send packets to DUT port-1.The outer v4 header has the destination addresses 138.0.11.8. 

    We should expect that all egress packets (100%) are IPinIP (4in4) encapped to 203.0.113.1.  

    Furthermore, the encapped/tunneled packets should be distributed hierarchically per the specified weights. 

    Shutdown DUT port-2, port-3, and port-4. Validate that corresponding traffic that was encapped to 203.0.113.1 should now be encapped with 203.0.113.100 

## Protocol/RPC Parameter coverage

## Config parameter coverage

## Telemery parameter coverage
