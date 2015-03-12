#! /usr/bin/python
import subprocess
import sys
import time
import argparse

DIFF = False
FIRST = []


def get_floating_ips():
    sql = """SELECT fip.floating_ip_address
FROM   neutron.floatingips               AS fip
JOIN   neutron.ports                     AS p
JOIN   neutron.securitygroupportbindings AS sgb
JOIN   neutron.securitygrouprules        AS sgr
JOIN
       (
                SELECT   ins.uuid ,
                         Count(p.id)    AS count
                FROM     nova.instances AS ins
                JOIN     neutron.ports  AS p
                WHERE    ins.uuid=p.device_id
                AND      ins.deleted=0
                AND      ins.vm_state='active'
                AND      ins.task_state IS NULL
                GROUP BY ins.uuid ) AS i
WHERE  fip.fixed_port_id=p.id
AND    p.admin_state_up=1
AND    sgb.port_id=p.id
AND    sgb.security_group_id=sgr.security_group_id
AND    sgr.direction='ingress'
AND    sgr.protocol='icmp'
AND    sgr.remote_ip_prefix='0.0.0.0/0'
AND    p.device_id=i.uuid
AND    i.count=1;"""
    floating_ips = [ip for ip in subprocess.Popen(
                    ["mysql", "-sNe", sql],
                    stdout=subprocess.PIPE).communicate()[0].split("\n") if ip]
    return floating_ips


def get_public_ips(net_uuid):
    if not net_uuid:
        return None
    sql = """SELECT ipa.ip_address
FROM   neutron.ports                     AS p
JOIN   neutron.ipallocations             AS ipa
JOIN   neutron.securitygroupportbindings AS sgb
JOIN   neutron.securitygrouprules        AS sgr
JOIN
       (
                SELECT   ins.uuid ,
                         Count(p.id)    AS count
                FROM     nova.instances AS ins
                JOIN     neutron.ports  AS p
                WHERE    ins.uuid=p.device_id
                AND      ins.deleted=0
                AND      ins.vm_state='active'
                AND      ins.task_state IS NULL
                GROUP BY ins.uuid ) AS i
WHERE  ipa.network_id='""" + net_uuid + """'
AND    ipa.port_id=p.id
AND    p.admin_state_up=1
AND    p.device_owner LIKE "compute:%"
AND    sgb.port_id=p.id
AND    sgb.security_group_id=sgr.security_group_id
AND    sgr.direction='ingress'
AND    sgr.protocol='icmp'
AND    sgr.remote_ip_prefix='0.0.0.0/0'
AND    p.device_id=i.uuid
AND    i.count=1;"""
    public_ips = [ip for ip in subprocess.Popen(
        ["mysql", "-sNe", sql],
        stdout=subprocess.PIPE).communicate()[0].split("\n") if ip]
    return public_ips


def ping(ip):
    return subprocess.call(["ping", "-c", "1", "-w", "1", ip],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def ping_loop(net_uuid=None):
    pingable_ips = get_public_ips(net_uuid) if net_uuid else []
    pingable_ips += get_floating_ips()
    total = len(pingable_ips)
    fail_list = []
    global DIFF
    global FIRST
    for ip in pingable_ips:
        if DIFF and FIRST and ip in FIRST:
            result = "?"
        else:
            result = ping(ip)
        sys.stdout.write(str(result))
        sys.stdout.flush()
        if result == 1:
            fail_list.append(ip)
    if DIFF:
        if FIRST:
            diff_list = [ip for ip in fail_list if ip not in FIRST]
            print "\n@DIFF: [%s] %s/%s: %s" % (total, len(diff_list),
                                               len(fail_list), diff_list)
        else:
            FIRST = fail_list
            print "\nFIRST: [%s] %s/%s: %s" % (total, len(fail_list),
                                               len(fail_list), fail_list)
    else:
        print "\n[%s] %s: %s" % (total, len(fail_list), fail_list)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--net_id", help="Include netwrok <net-id>")
    parser.add_argument("--diff", action="store_true",
                        help="Only print diff ips compare with first round",
                        default=False)
    args = parser.parse_args()

    public_network_uuid = args.net_id if args.net_id else None
    if args.diff:
        DIFF = True
    while True:
        start = time.time()
        print time.strftime("%x %X")
        ping_loop(public_network_uuid)
        end = time.time()
        if int(end-start) < 2:
            time.sleep(2- int(end-start))
