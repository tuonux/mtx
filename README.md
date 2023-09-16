# MTX Framework

Just a funny porting of the real Metasploit Framework written in GreyScript language for Grey Hack game and as Metasploit... **_MTX Framework is Open Source!_**

Author: tuonux \<tuonux0@gmail.com\>

<iframe width="100%" height="300" src="https://www.youtube.com/embed/QtLqkCrDPZY?si=0TChQOkc5m7oqXTK" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

### Changelog

    1.0.1
        - NEW:      "switch" command for metexpreter that allow you to upload mtx, metaxploit and crypto on already metexpreter shell type session
        - IMPROVE:  "ipconfig" allow you to set network configuration directly with "ipconfig <device> <lan ip> <gateway>
        - FIX:      hashdump regex function get non hex characters
        - FIX:      upload and download function set group and owner of the current shell session

## Play on Grey Hack like a pseudo-real hacker!

MTX Framework offer the possibility to get you in a pseudo-real hacker experience like the famous Metasploit command line based interface!

## Scan, Discover, Exploit and more!

You have a lot o commands to perform and hack your target in the game!

## See the MTX Framework in action:

### Build the framework first

Just copy and paste the **mtx.src** code in **CodeEditor.exe** and build it with name **mtx**

### Launch the mtx framework and wait the loading

    tuonux@PC:/home/tuonux/$ mtx

               _           __                                             _
              | |         / _|                                           | |
     _ __ ___ | |___  __ | |_ _ __ __ _ _ __ ___   _____      _____  _ __| | __
    | '_ ` _ \| __\ \/ / |  _| '__/ _` | '_ ` _ \ / _ \ \ /\ / / _ \| '__| |/ /
    | | | | | | |_ >  <  | | | | | (_| | | | | | |  __/\ V  V / (_) | |  |   <
    |_| |_| |_|\__/_/\_\ |_| |_|  \__,_|_| |_| |_|\___| \_/\_/ \___/|_|  |_|\_\

    Version 1.0.0 | made by tuonux ( https://github.com/tuonux/mtx )

    + -- -=[       exploits:       723       ]=- -- +
    + -- -=[       shells:         63        ]=- -- +
    + -- -=[       files:          49        ]=- -- +
    + -- -=[       lanswitchers:   45        ]=- -- +
    + -- -=[       generics:       477       ]=- -- +
    + -- -=[       passwchangers:  35        ]=- -- +
    + -- -=[       computers:      44        ]=- -- +
    + -- -=[       fwshutdowns:    10        ]=- -- +

### Discover router, firewall and ports info with the MTX Framework built-in nmap command

    mtx > nmap 1.1.1.1

    [*] Nmap - Router IP: 192.168.0.1
    [*] Nmap - Router version: 1.0.0
    [+] Nmap - No firewall rules
    [+] Nmap - Discovered open port 22
    [+] Nmap - Port 22 respond with service ssh 1.0.0 on lan 192.168.0.2
    [+] Nmap - Discovered open port 25
    [+] Nmap - Port 25 respond with service smtp 1.0.0 on lan 192.168.0.2
    [-] Nmap - Discovered closed port 3306
    [+] Nmap - Discovered open port 22288
    [+] Nmap - Port 22288 respond with service ssh 1.0.0 on lan 192.168.0.3

### Scan the target on port 22 with the MTX Framework built-in scan command

    mtx > scan 1.1.1.1 22

    [+] 1.1.1.1:22 - Successfully connected!
    [*] 1.1.1.1:22 - Dump MetaLib from the targeted service...
    [+] 1.1.1.1:22 - Current MetaLib loaded: libssh.so => 1.0.0
    [*] 1.1.1.1:22 - Perform a scan on libssh.so...
    [###################################]==[ 100% ]
    [+] 1.1.1.1:22 - Library scan completed successfully!
    [+] 1.1.1.1:22 - Vulnerables addresses founds: 6
    [*] 1.1.1.1:22 - Perform scan on 0x761FC8FE...
    [+] 1.1.1.1:22 - Scan on 0x761FC8FE completed successfully!
    [*] 1.1.1.1:22 - Unsafe check: string copy in cii_freque. Buffer overflow.
    [*] 1.1.1.1:22 -  Require: Using namespace kernel_module.so compiled at version >= 1.0.0
    [*] 1.1.1.1:22 -  Require: Checking registered users equal to 1.
    [*] 1.1.1.1:22 -  Require: 2 port forwarding configured from router to the target computer.
    [*] 1.1.1.1:22 - Unsafe check: loop in array ber. Buffer overflow.
    [*] 1.1.1.1:22 - Unsafe check: string copy in zelistextbuttondinged. Buffer overflow.
    [*] 1.1.1.1:22 - Unsafe check: loop in array pos++. Buffer overflow.
    [*] 1.1.1.1:22 -  Require: 1 port forwarding configured from router to the target computer.
    [*] 1.1.1.1:22 -  Require: Using namespace init.so compiled at version >= 1.0.0
    [*] 1.1.1.1:22 - Unsafe check: string copy in bool. Buffer overflow.
    [*] 1.1.1.1:22 -  Require: Checking registered users equal to 3.
    [*] 1.1.1.1:22 -  Require: 1 port forwarding configured from router to the target computer.
    [*] 1.1.1.1:22 - Dump exploit info...
    Searching required library kernel_module.so => found!

    Starting attack...success!
    Privileges obtained from user: Elvin
    [+] Successfully created new exploit: exploit/shell/ssh/100_0x761FC8FE_cii_fr

    ...snip...

### Reload the list of the available modules and exploits...

    mtx > reload

    [+] Exploits list reloaded

### Display the available exploits list

    mtx > show exploits

    Exploits
    --------

    #   Name                                            Disclosure Date  Rank       Description
    -   ----                                            ---------------  ----       -----------
    1   exploit/shell/ssh/100_0x761FC8FE_cii_fr         23/Mar/2000      Normal     Overflow on libssh.so 1.0.0 with forwarded port
    2   exploit/shell/ssh/100_0x761FC8FE_ber            23/Mar/2000      Excellent  Vulnerable libssh.so 1.0.0
    3   exploit/shell/ssh/100_0x22DAA7A5_pend_c         23/Mar/2000      Good       Library libssh.so 1.0.0 with an active user
    4   exploit/file/ssh/100_0x761FC8FE_zelist          23/Mar/2000      Excellent  Overflow on libssh.so 1.0.0
    5   exploit/file/ssh/100_0x11DF7AA4_head            23/Mar/2000      Excellent  Library libssh.so 1.0.0
    6   exploit/file/ssh/100_0x22DAA7A5_peopb           23/Mar/2000      Excellent  Library libssh.so 1.0.0

    ...snip...

### Use and load the module to perform an attack

    mtx > use exploit/shell/ssh/100_0x761FC8FE_cii_fr

    [+] Module exploit/shell/ssh/100_0x761FC8FE_cii_fr charged

### Show available options for the current module

    mtx exploit(shell/ssh/100_0x761FC8FE_cii_fr) > show options

    Name      Current Setting  Required  Description
    ====      ===============  ========  ===========
    RHOST     127.0.0.1        yes       Target IP Address
    RPORT     22               yes       Target Port Number
    ARGUMENT                   no

### Set the RHOST option

    mtx exploit(shell/ssh/100_0x761FC8FE_cii_fr) > set rhost 1.1.1.1

    RHOST => 1.1.1.1

### Set the RPORT option

    mtx exploit(shell/ssh/100_0x761FC8FE_cii_fr) > set rport 22

    RPORT => 22

### Check if the target maybe is vulnerable to our exploit

    mtx exploit(shell/ssh/100_0x761FC8FE_cii_fr) > check

    [*] 1.1.1.1:22 - Attempt to connect on remote host...
    [+] 1.1.1.1:22 - Succesfully connected!
    [+] Check done! The target seems vulnarable to this exploit

### It's time to exploit it!

    mtx exploit(shell/ssh/100_0x761FC8FE_cii_fr) > run

    [*] 1.1.1.1:22 - Attempt to connect on remote host...
    [+] 1.1.1.1:22 - Succesfully connected!
    [+] Library check: OK
    [*] 1.1.1.1:22 - Attempt to oveflow the target library
    Searching required library kernel_module.so => found!

    Starting attack...success!
    Privileges obtained from user: Elvin

    [+] Command shell session 1 opened (1.1.1.1 -> 113.235.47.161) at 23/Mar/2000 - 06:34

### Awesome! We get a shell session as user Elvin and we get in metexpreter console command!

### Maybe we want all the hashes stored in the Elvin file system computer? :D

    metexpreter > hashdump

    root                 |  a84b5b574449d99b7eef483b29dec122  |  /etc/passwd
    Elvin                |  4297f44b13955235245b2497399d7a93  |  /etc/passwd
    Mireser              |  4297f44b13955235245b2497399d7a93  |  /etc/passwd
    Elvin@ayloriad.info  |  2cb40735230713cbf845fdddfb07e7ff  |  /home/Elvin/Config/Mail.txt
    AWJ0rKNj             |  a5224c38c90be4f490df437ce13086f5  |  /home/Elvin/Config/Bank.txt

### WOW! We get more then one hash from the system...

### Mabe it's time to decipher the root hash?

    etexpreter > decipher a84b5b574449d99b7eef483b29dec122

    [###################################]==[ 100% ]
    [+] a84b5b574449d99b7eef483b29dec122 -> iGb1Qn6n

### We got a root password... but... how if we try to "get the system?" :D

### We can do it with the MTX Framework built-in getsystem command

    metexpreter > getsystem

    [*] Try to get /etc/passwd...
    [+] /etc/passwd readable!
    [*] Try to get root hash...
    [+] Root hash -> a84b5b574449d99b7eef483b29dec122
    [*] Attempt to decipher root hash...
    [###################################]==[ 100% ]
    [+] a84b5b574449d99b7eef483b29dec122 -> iGb1Qn6n
    [*] Write reverse shell code on remote machine...
    [+] Reverse shell code writed successfully!
    [*] Attempt to build reverse shell...
    [+] Reverse shell code build successfully!
    [*] Attempt to launch reverse shell binary...

    [+] Command shell session 2 opened (1.1.1.1 -> 113.235.47.161) at 23/Mar/2000 - 07:43
    [+] Getsystem command successfully done! New root reverse shell acquired!

### Oh oh! We got a root reverse shell with session id 2!

### Quit the current session

    metexpreter > quit

### We are back and ready to show all the sessions now!

    mtx exploit(shell/ssh/100_0x761FC8FE_cii_fr) > sessions -l

    Active sessions
    ---------------

    #  Name  Information  Type    Connection
    -  ----  -----------  ----    ----------
    1        Shell/root   Shell   1.1.1.1 -> 113.235.47.161

### We got it! Time to interact with new shell id now!

    mtx exploit(shell/ssh/100_0x761FC8FE_cii_fr) > sessions -i 1

    [*] Starting interation with session 1...

### Who we are?

    metexpreter > getuid

    [*] Current user is root

### GOAL! Just leave a message with the write session :)

    metexpreter > write hacked.txt

    Write session

    Usage:

    :d: Delete last line
    :w: End write session and print content in hacked.txt
    :q: Quit write session without print content

    - Hello,
    - your system need to be upgraded as soon possibile.
    -
    - You have an outdate libssh.so library.
    -
    - Hope it help you.
    -
    - Cya.
    -
    - - tuonux
    -
    - :w

### See the content of the hacked.txt file

    metexpreter > cat hacked.txt

    Hello,
    your system need to be upgraded as soon possibile.

    You have an outdate libssh.so library.

    Hope it help you.

    Cya.

    - tuonux

### And we helped others today too... But how if we want to scan the internal network with MTX Framework?

## We can just perform a "switch"!

    metexpreter > switch

    [*] Upload /home/tuonux/mtx

    100%	719.6 KB/s	0 sec (6.1 MB of 6.1 MB copied)
    Processing...

    [+] /home/tuonux/mtx -> /root/mtx
    [*] Upload /lib/metaxploit.so

    100%	711.1 KB/s	0 sec (7380 Bytes of 7380 Bytes copied)
    Processing...

    [+] /lib/metaxploit.so -> /root/metaxploit.so
    [*] Upload /lib/crypto.so

    100%	750.0 KB/s	0 sec (0 Bytes of 0 Bytes copied)
    Processing...

    [+] /lib/crypto.so -> /root/crypto.so
    [+] MTX Framework uploaded successfully

    [*] Launch MTX Framework binary


               _           __                                             _
              | |         / _|                                           | |
     _ __ ___ | |___  __ | |_ _ __ __ _ _ __ ___   _____      _____  _ __| | __
    | '_ ` _ \| __\ \/ / |  _| '__/ _` | '_ ` _ \ / _ \ \ /\ / / _ \| '__| |/ /
    | | | | | | |_ >  <  | | | | | (_| | | | | | |  __/\ V  V / (_) | |  |   <
    |_| |_| |_|\__/_/\_\ |_| |_|  \__,_|_| |_| |_|\___| \_/\_/ \___/|_|  |_|\_\

    Version 1.0.1 | made by tuonux ( https://github.com/tuonux/mtx )

    + -- -=[       exploits:       0         ]=- -- +

    mtx >

### Do you want to upgrade your exploits db?

    Try to use the "discover" command!

## MTX Framework Filesystem storage

Every modules are stored under the folder /usr/share/mtx/exploits

There are different modules type that corrispond to own folders

Example:

    shell          Exploit that attempt to obtain a shell session
    computer       Exploit that attempt to obtain a computer session
    file           Exploit that attempt to obtain a file session
    lanswitcher    Exploit that attempt to route a router and gain a shell on a internal target IP machine
    passwchanger   Exploit that attempt to change a non-root user password with a new provided password
    fwshutdown     Exploit that attempt to shutdown a router firewall
    generic        Exploit that are not tested 100% or that need more requirements in order to be used

For example, shell exploits for ssh service are stored in this path

    /usr/share/mtx/exploits/shell/ssh/<esploit_name>.src

## Write your own exploit compatible with framework!

Yes, **you read right**!

With MTX you have the possibility to **write your own exploit in GreyScript** exatly like Metasploit permit to do!

#### The magic of the <b>get_custom_object.MTXExploit</b>:

This object is the core of the entire framework and exploits comunication!

In this example you can see how you can write an exploit!

```
// This module requires MTX Framework:     https://github.com/tuonux/mtx
// Current source:              		   https://github.com/tuonux/mtx

MTXExploit = get_custom_object.MTXExploit
MTXExploit.name  = "<enter the exploit name>"
MTXExploit.description = "<enter the exploit description>"
MTXExploit.author = "<enter the exploit author>"
MTXExploit.rank = "<enter a rank like Low|Average|Normal|Good|Great|Excellent>"
MTXExploit.privileged = "<enter 1|0 if your exploit get elevate privileges>"
MTXExploit.disclosure_date = "<enter the disclosure date>"
MTXExploit.options["<enter the option 1>"] = {"required": <is required? 1|0>, "default": "<default value>", "description": "<option description>"}
MTXExploit.options["<enter the option 2>"] = {"required": <is required? 1|0>, "default": "<default value>", "description": "<option description>"}
MTXExploit.options["<enter the option 3>"] = {"required": <is required? 1|0>, "default": "<default value>", "description": "<option description>"}

// Every exploit need a check funtion in order to declare if the target is vulnerable or not
// Mabybe a check on the library and the library version can help!
// The options Map contains the value of the options set by the user.
MTXExploit.check = function(options)
    target          = options.RHOST
    port            = options.RPORT.to_int
    argument        = options.RLANIP
    library_name    = "kernel_router.so"
    library_version = "1.0.5"
    address         = "0x4A033B44"
    variable        = "mored_"
    print_info("Attempt to connect on remote host...", target+":"+port)
    net = metaxploit.net_use(target, port)
    if not net then return print_error("Unable to connect to remote host", target+":"+port)
    print_good("Succesfully connected!", target+":"+port)
    if net.dump_lib.lib_name != library_name or net.dump_lib.version.to_int > library_version.to_int then return print_error("Different library. Required: kernel_router.so <= 1.0.5 ", target+":"+port)
    return true
end function

// This is the run() function to see your exploit in action and perform overflows and other commands that you need!
// The register_session(overflow_result) make a new sessions registered to the MTX Framework
// The options Map contains the value of the options set by the user.
MTXExploit.run = function(options)
    target          = options.RHOST
    port            = options.RPORT.to_int
    argument        = options.RLANIP
    library_name    = "kernel_router.so"
    library_version = "1.0.5"
    address         = "0x4A033B44"
    variable        = "mored_"
    print_info("Attempt to connect on remote host...", target+":"+port)
    net = metaxploit.net_use(target, port)
    if not net then return print_error("Unable to connect to remote host", target+":"+port)
    print_good("Succesfully connected!", target+":"+port)
    if net.dump_lib.lib_name != library_name or net.dump_lib.version.to_int > library_version.to_int then return print_error("Different library. Required: kernel_router.so <= 1.0.5 ", target+":"+port)
    print_good("Library check: OK")
    print_info("Attempt to oveflow the target library", target+":"+port)
    overflow_result = net.dump_lib.overflow(address, variable, argument)
    if not overflow_result then return print_error("Unable to perform an overflow to the target library. Try to check the requirements")
    register_session(overflow_result)
    return true
end function

```

It's a good pratice store your exploits under "custom" directory like example:

    /usr/share/mtx/exploits/custom/<my_exploit_name>.src

After created a custom exploit, you need to use "reload" command if you have mtx running.

### Just keep in mind:

There are several function that you can use in your exploit code that extends MTX Framework.

    metaxploit                               The metaxploit class is alredy included. You don't need to include again.
    crypto                                   The crypto class is alredy included. You don't need to include again.

    print_info(<str>)                        Print string in MTX Framework info style
    print_error(<str>)                       Print string in MTX Framework error style and return false
    print_good(<str>)                        Print string in MTX Framework error style and return true

    register_session(<shell/computer/file>)  Register a new metexpreter session

    MTXExploit.check                         Needs to return <true|false>

## mtx console commands

    ?            Help menu
    cd           Change the current working directory
    connect      Communicate with an ssh host
    exit         Exit the console
    help         Help menu
    info         Displays information about one or more modules
    quit         Exit the console
    reload       Reloads all modules from all defined module paths
    search       Searches module names and descriptions
    sessions     Dump session listings and display information about sessions
    set          Sets a context-specific variable to a value
    setg         Sets a global variable to a value
    show         Displays modules of a given type, or all modules
    unset        Unsets one or more context-specific variables
    unsetg       Unsets one or more global variables
    use          Selects a module by name
    nmap         Scan the target to get router info, firewall rules and info about target ports
    discover     Scan the globe with random IPs and write the exploits localy
    scan         Scan target port and if vulnerable write the exploits localy

## metexpreter console commands

    ?            Help menu
    background   Moves the current session to the background
    exit         Terminates a meterpreter session
    help         Help menu
    quit         Terminates the meterpreter session
    write        Open a write session
    cat          Read and output to stdout the contents of a file
    cd           Change directory on the victim
    del          Delete a file on the victim
    download     Download a file from the victim system to the attacker system
    getlwd       Print the local directory
    getwd        Print working directory
    lcd          Change local directory
    lpwd         Print local directory
    ls           List files in current directory
    mkdir        Make a directory on the victim system
    pwd          Print working directory
    rm           Delete a file
    rmdir        Remove directory on the victim system
    upload       Upload a file from the attacker system to the victim
    ipconfig     Displays network interfaces with key information including IP address
    execute      Executes a /bin command
    getuid       Get the user that the server is running as
    kill         Terminate the process designated by the PID
    ps           List running processes
    shell        Opens a command shell on the victim machine
    getsystem    Try to gain sysadmin privileges
    hashdump     Find and grab the hashes on entire filesystem
    decipher     Try to decipher a provided hash
    switch       Upload mtx, metaxploit and crypto and execute mtx on vicitm machine

## Next Goals

- Possibility to charge payloads too

## Contributing

If you want to contributing to this project, you can make pull requests on this repository.

## License

This code is distribuited under MIT License.

    Copyright (c) 2023 tuonux <tuonux0@gmail.com>

    Permission is hereby granted, free of charge, to any person
    obtaining a copy of this software and associated documentation
    files (the "Software"), to deal in the Software without
    restriction, including without limitation the rights to use,
    copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following
    conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
    OTHER DEALINGS IN THE SOFTWARE.
