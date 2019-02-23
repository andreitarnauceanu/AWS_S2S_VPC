#!/usr/bin/python2.7
import boto3
import re
import sys
import os
from dns import resolver
from IPy import IP


def create_customer_gateway(ip_address):
    print("Creating Customer Gateway...")
    return client.create_customer_gateway(
        BgpAsn=65000,
        PublicIp=ip_address,
        Type='ipsec.1',
        DryRun=False
    )


def create_vpn_gateway():
    print('Creating VPN Gateway...')
    return client.create_vpn_gateway(
        Type='ipsec.1',
        DryRun=False
    )


def create_vpn_connection(customer_gateway_id, vpn_gw_id):
    print('Creating VPN Connection...')
    return client.create_vpn_connection(
        CustomerGatewayId=customer_gateway_id,
        VpnGatewayId=vpn_gw_id,
        Type='ipsec.1',
        DryRun=False
    )


def save_gateway_config(vpn_conn, filename):
    gateway_config = vpn_conn.get('CustomerGatewayConfiguration')
    print("Configuration saved. (vpn_config.xml)")
    with open(filename, 'w') as f:
        f.write(gateway_config)


def hostname_to_ip(hostname):
    # This will return only the first ip address returned by the dns server
    res = resolver.Resolver(configure=False)
    res.nameservers = ['8.8.8.8', '8.8.4.4']
    response = res.query(hostname, 'a')
    ip_address = response[0].address
    return ip_address


def hostname_or_ip(address):
    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    is_IP = pat.match(address)
    if is_IP:
        pass
    else:
        address = hostname_to_ip(address)
    if IP(address).iptype() == 'PUBLIC':
        return address
    else:
        raise ValueError("Private IP addresses are not accepted.")


def attach_vpn_gw_to_vpc(vpn_gw_id):
    response = client.describe_vpcs(
        Filters=[],
        VpcIds=[],
        DryRun=False
    )
    vpcs = response.get('Vpcs')
    if len(vpcs) == 1:
        vpc_id = vpcs[0].get('VpcId')
    else:
        # TODO Display a list of vpcs
        pass

    print("Attaching VPN gateway to VPC")
    return client.attach_vpn_gateway(
        VpcId=vpc_id,
        VpnGatewayId=vpn_gw_id,
        DryRun=False
    )


def get_att_vpc(vpn_gw_id):
    vpc_att = client.describe_vpn_gateways(VpnGatewayIds=[vpn_gw_id, ]).get('VpnGateways')[0].get('VpcAttachments')
    if len(vpc_att) != 0:
        return vpc_att[0].get('State'), vpc_att[0].get('VpcId')
    else:
        return None, None


def main():
    assert sys.version_info.major == 2 and sys.version_info.minor == 7, 'Wrong python version. 2.7 required'

    public_ipAddress = hostname_or_ip(sys.argv[1])
    tags = [{'Key': 'Name', 'Value': sys.argv[1]}]
    check_customer_gateway = client.describe_customer_gateways(
        Filters=[
            {
                'Name': 'ip-address',
                'Values': [public_ipAddress]
            },
            {
                'Name': 'state',
                'Values': ['available', 'pending']
            }
        ],
        DryRun=False
    )

    if len(check_customer_gateway.get('CustomerGateways')) != 0:
        print("Customer gateway already in place!")
        customer_gateway = check_customer_gateway.get('CustomerGateways')[0]
        customer_gw_id = customer_gateway.get('CustomerGatewayId')
        check_vpn_connection = client.describe_vpn_connections(
            Filters=[
                {
                    'Name': 'customer-gateway-id',
                    'Values': [customer_gw_id]
                },
                {
                    'Name': 'state',
                    'Values': ['available', 'pending']
                }
            ],
            DryRun=False
        )
        if len(check_vpn_connection.get('VpnConnections')) != 0:
            print('VPN connection already in place.')
            vpn_connection = check_vpn_connection.get('VpnConnections')[0]
            vpn_gw_vpc_att_state, vpn_gw_vpc_att_id = get_att_vpc(vpn_connection.get('VpnGatewayId'))
            if vpn_gw_vpc_att_state in ['attaching', 'attached']:
                print('VPN gateway attached to {} VPN'. format(vpn_gw_vpc_att_id))
            else:
                attach_vpn_gw_to_vpc(vpn_connection.get('VpnGatewayId'))
            save_gateway_config(vpn_connection, 'vpn_config.xml')
    else:
        customer_gateway = create_customer_gateway(public_ipAddress)
        client.create_tags(Tags=tags, Resources=[customer_gateway.get('CustomerGateway').get('CustomerGatewayId')]);
        vpn_gateway = create_vpn_gateway()
        client.create_tags(Tags=tags, Resources=[vpn_gateway.get('VpnGateway').get('VpnGatewayId')]);
        vpn_connection = create_vpn_connection(
            customer_gateway.get('CustomerGateway').get('CustomerGatewayId'),
            vpn_gateway.get('VpnGateway').get('VpnGatewayId')
        )
        client.create_tags(Tags=tags, Resources=[vpn_connection.get('VpnConnection').get('VpnConnectionId')]);
        attach_vpn_gw_to_vpc(vpn_gateway.get('VpnGateway').get('VpnGatewayId'))
        save_gateway_config(vpn_connection.get('VpnConnection'), 'vpn_config.xml')


if __name__ == "__main__":
    client = boto3.client(
        'ec2',
        region_name='us-east-1',
        aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
        aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY']
    )
    main()
