# Fake-Gree-server
Fake Gree server implementation to mitigate the need to let Gree/Syen HVAC units do homecalls at all, starting from the registration.
**It works for both Gree and Syen HVAC units** _(As Syen is mostly produced by Gree. My Syen literally has a Gree WiFi module with a Gree MAC address)_

# Why?
Because Gree and Syen HVAC units' WiFi control does not work unless they can register to a server successfully and then keep a heartbeat connection up from time to time. I really dislike the idea of having any of my IoT devices wander the internet on their own, despite the fact I (as any sane person should too) keep them in a very well separated IoT network. If you can prevent any home-calls, why shouldn't you? :)

# How it's working
You reset your unit's WiFi, you register following the registration procedure described in the next points (and in the fake server log on startup) and you forget about it.

# Prerequisites
There are some things you need to have working before you can use this hack solution:
* A DNS server serving (at least) the (separate?) network onto which the HVAC unit will be connected to
* A DNS override of `dis.gree.com` to the IP address of this fake server _(implicated reserving a static ip for the server)_
* You could additionally block all other connections sourcing from the HVAC unit except for DNS requests towards your DNS server and TCP/1812 towards this fake server
* For the registration / activation process you'll need a WiFi and Python3 capable device _(laptop or possibly some phones)_

# Setting it all up
1. Download, review, edit to your needs or simply jump to building & running the fake sever. _(The bare minimum you should probably change is the IP address in the docker-compose.yml file to fit into your subnet in which the HVAC unit will reside too.)_
2. Turn off the HVAC unit and reset the WiFi settings _(MODE + WIFI usually)_
3. Wait ~ 2 minutes and once the HVAC unit's WiFi comes online, connect to it from a laptop or some other device! (SSID will be the last few bytes of its MAC address, the password is `12345678`)
4. Run `python3 register.py YOUR_WIFI'S_SSID YOUR_WIFI'S_PASSWORD`
5. In a few seconds the fake server should be receiving all sorts of connections and everything will be working.

# Limitations
* I don't think the usualy Gree applications work like this, at all. They don't really, for me, at least. **Homeassistant** is an amazing project and it works flawlessly, however! _(Including the automatic discovery and all!)_ Check it out, so much better than the stock apps anyway [with zero homecalls :)] )_
* Nothing else really. After setting all up I tried shutting down the fake server for a few hours and then firing it back up. The HVAC unit tolerated it nicely, nothing stopped working. I can imagine having the fake server not running for a very long time could cause the HVAC unit to lose its s#*t and start the discovery process again but that would work just fine too since the DNS for the discovery server _(dis.gree.com)_ is overriden :)
* Absolutely worst case you need to do the registration procedure again. It takes < 1 min. and I never had to do it again, save for the testing. _(In HomeAssistant after re-registrations you may need to reload the Gree module - no need to restart HomeAssistant!)_

# Saying thanks..
* .. to tomikaa87 for his project gree-remote: https://github.com/tomikaa87/gree-remote
* .. to emtek-at for their project GreeAC-DummyServer: https://github.com/emtek-at/GreeAC-DummyServer
