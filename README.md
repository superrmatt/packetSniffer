# Packet Sniffer

Simple packet sniffer made in Perl. <br/>
Designed for use in linux, to push all sniffed packets and most header variables into a database. <br/>
Also prints values to the command line. <br/>
<br/>
Parses each packet into a human readable format.<br/>
This sniffer will grab all traffic in your network. I have tested it on enterprise style networks with large traffic volume and have encountered no issues.<br/>
<br/>
Feel free to use, if you are going to use, don't forget to update the information for the database, its username, and its password. Or else it obviously won't work.<br/>
<br/>
the var i is a set number, to tell the packet sniffer how many times to run. While i < (some value) it will run.
Both i and (some vlaue) can be easily edited to suit one's needs. For continuous run until interupted with a kill command (^c for example), simply edit the while loop to say while(true){}. <br/>
<br/>
The primary purposes I used this for were:
    - Network enumeration for penetration tests.
    - Information gathering for an anomoly based intrusion detection system I made.
    - Fun side project to learn some basic networking, and perl.
Contact with any other questions. <br/>
<br/>
I do not condone malicious use. Nor will I tell you how this can be used for malicious purposes.