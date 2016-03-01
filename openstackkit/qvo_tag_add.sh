#! /bin/bash

if [ -z "$1" ]; then
 echo 'qvo_tag_add.sh  <vm-uuid>'
 exit 1
fi

echo $1

port_ids=$(nova interface-list $1 |depipe|grep -v ^Port|awk '{print $2}')

for p in $port_ids; do
  net_id=$(neutron port-show $p |depipe|grep  network_id | awk '{print $2}')
  vlan_id=$(neutron net-show $net_id | depipe|grep segmentation_id|awk '{print $2}')
  host=$(neutron port-show $p |depipe|grep host_id | awk '{print $2}')
  qvo_dev='qvo'${p:0:11}
  ssh $host /usr/bin/ovs-vsctl show |grep -q $qvo_dev
  qvo_on_br=$?
  ssh $host /usr/bin/ovs-vsctl show |grep -A2 'Port \"$qvo_dev\"' |grep -q tag
  qvo_has_tag=$?
  tap_dev='tap'${p:0:11}
  ssh $host /usr/bin/ovs-vsctl show |grep -q $tap_dev
  tap_on_br=$?
  if [[ $qvo_on_br == 1 && $tap_on_br == 0 && $qvo_has_tag == 0 ]];then
     tag_id=$(ssh $host  "/usr/bin/ovs-ofctl dump-flows  br-int|grep $vlan_id" |awk -F, '{print $10}' |awk -F: '{print $2}' )
     echo $tag_id
     ssh $host "/usr/bin/ovs-vsctl --timeout=10 set Port $qvo_dev tag=$tag_id"
  else
     echo "Ignored because:"
     echo " - qvo on bridge $qvo_on_br"
     echo " - tap on bridge $tap_on_br"
     echo " - qvo has tag $qvo_has_tag"
  fi
done
