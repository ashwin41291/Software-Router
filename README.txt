Software Router:
Project Members: Aswin Srinivasan - ashwin41291@email.arizona.edu
			Jasmine Dhillon - dhillon@email.arizona.edu
				 
Giving credits where its due:
Checksum computation - Peterson & Dave pg.95
Length Calculations concepts - Network Sorcery

As far as we tested, router seems to be working perfectly fine implementing all the
functionalities required as per the test document.
We have tried covering the edge cases too and found to be breezing through.
If unexpected outcome comes, just let us know so that we could fix it for our second phase.

Results:
1. sending simultaneous ping requests - works fine
2. Doing a wget to all the servers behind the router - works fine
3. Downloading a 64MB file from all servers behind the router - works fine
4. disconnected the interface between server and router and did a ping
			to the server - returns host unreachable for every 6th packet
								- works fine
5. ping to the router interfaces - works fine
6. ping to all servers behind the router - works fine.
7. traceroute to all servers behind the router - works fine
8. test1.pl scripts all commands - working fine.
