# HackTheBox - Debugging Interface

https://app.hackthebox.eu/challenges/Debugging-Interface

First we download the challenge file and extract it.

We get the file `debugging_interface_signal.sal`, we run the command `file debugging_interface_signal.sal` and we get this result:

```
debugging_interface_signal.sal: Zip archive data, at least v2.0 to extract
```

Lets extract the file then, we will get 2 files:
```
digital-0.bin
meta.json
```

Lets open `digital-0.bin` in a hexdump: `hexdump -C digital-0.bin`, and we notice the header of the file:

```
00000000  3c 53 41 4c 45 41 45 3e  01 00 00 00 64 00 00 00  |<SALEAE>....d...|
```

Looks like this file can be opened with the famous Logic Analyzer SALEAE.

We can downlaod a free copy, install it, open it, and then open the file `debugging_interface_signal.sal`.

We open the Analyzer tab in the top right bar.

We notice that we have only one channel (`Channel 0`), so its most likely that the debugging interface used was UART so we will select `Async Serial` from the top right, once clicked, a dialog will show up, and we can select `Channel 0` from the `Input Channel`.

Now we need to select a proper `Bit rate`, so we will have to calculate it.

To calculate the bit rate, we zoom on the beginning of the data (Channel 0), hover the cursor on top of the first block of data:

![Calculating the bit rate](images/Screenshot%20at%202021-07-06%2023-08-46.png)

We notice the value `32.02 µs`, which is in microseconds so we simply divide it by 1000000 to get the transfer rate by seconds, so 1000000 / 32.02 = 31230

Alright so now we have the bite rate per second

Now we can enter it in the `Async Serial` settings as such:

![Entering the calculated bit rate](images/Screenshot%20from%202021-07-06%2023-24-05.png?raw=true)

And we click save.

Now the data will be decoded using our new bit rate and we can see the data in a better format if we open the `Terminal`:

![Opening the Terminal](images/Screenshot%20at%202021-07-06%2023-24-52.png?raw=true)

**We scroll down and we can see the flag!**
