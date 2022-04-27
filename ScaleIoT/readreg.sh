register_names="flow_duration"

for r in `echo $register_names | awk -F' ' '{for(i=1;i<=NF;i++) print $i}'`
do
    echo "copyind data for register $r to $r.txt"
    echo "register_read $r" | simple_switch_CLI --thrift-port 9090 | grep "=" | cut -d"=" -f2 > $r.txt
    echo $?
done
