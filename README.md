# packetSniffer

simple packet sniffer made in Perl.
Designed for use in linux, to push all sniffed packets and most header variables into a database.
Also prints values to the command line.

Parses each packet into a human readable format. Database sold seperately;)

Feel free to use, if you are going to use, don't forget to update the information for the database, its username, and its password. Or else it obviously won't work.

the var i is a set number, to tell the packet sniffer how many times to run. While i < (some value) it will run.
Both i can be easily edited, as can the while loop. for continuous run until interupted with a kill command (^c for example), simply edit the while loop to say while(true){}.

Contact with any other questions.

I do not condone malicious use. Nor will I tell you how this can be used to crack a wifi password.