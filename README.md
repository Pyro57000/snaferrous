# snaferrous

snafflerish but rusty!



Currently it just looks for some hardcoded keywords to determine if a file has sensitive infomation, but it works!



# USAGE:

snaferrous [OPTIONS]



Options:

  -o, --outfile <OUTFILE>  path to save output file Defaults to not saving output.

      \--threads <THREADS>  number of threads to use, default to 10. 

                           Note thre thread count will be doubled, one set for share finder tasks, and one set for file and infor finding tasks.

  -t, --targets <TARGETS>  specific targets. should be comma separated.

  -v, --verbose            echo all found files to the console, regardless of keyword matching. (all files will still be saved to the log file)

  -h, --help               Print help (see more with '--help')

  -V, --version            Print version



# Compiling:

`git clone https://github.com/Pyro57000/snaferrous.git`

`cd snafferous`

`cargo build --target x86_64-pc-windows-gnu --release`

then your .exe will be in the targets/x86_64-pc-windows-gnu/release folder!



# Tool Output.

By default the tool will only print the found shares and files with keyword matches to the console.

If you give it the -v flag then it will print all files it finds to the console.

By default it only gives output to the console, but if you give it an outfile with the -o flag it will save findings to that file.

If it can't open the output file or write to it for any reason it will ask you if you want to continue without saving anyway.



Findings will be structured like the following:

shares - share found! {path to the share}

keyword matchs - keyword match at {path to the file}

file - file found at {path to the file}

