from p4utils.mininetlib.network_API import NetworkAPI
import time

net = NetworkAPI()

# Network general options
net.setLogLevel('info')
net.enableCli()

# Network definition

start = time.time()
net.addP4Switch('s1', cli_input='commands.txt')

net.setP4Source('s1','siot.p4')
net.addHost('h1')
net.addHost('h2')
net.addLink('s1', 'h1')
net.addLink('s1', 'h2')

# Assignment strategy
net.mixed()

# Nodes general options
net.enablePcapDumpAll()
net.enableLogAll()

# Start network
net.startNetwork()

end = time.time()
print(end-start)
