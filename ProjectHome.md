In Vista/Win7/Win8, many internet related process run at a low integrity level. The IPC for low-integrity processes are limited, so only ring0 driver can block process tree's network access effectively. integrity level doc: http://msdn.microsoft.com/en-us/library/bb625960.aspx

This demo project is based on ring3 IPC, it won't work well on latest windows. So, I decided to close this project.

Obviously, a firewall can block any processes' network access. But, it's hard to block a process tree to access network, because firewall always treat one process not a process tree as a object. Even some powerful firewalls provide such feature, they may be too heavy or need a commercial licence. So, I create this project to meet this requirement.