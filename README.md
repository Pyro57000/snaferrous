# snaferrous
snafflerish but rusty!

Currently it just looks for some hardcoded keywords to determine if a file has sensitive infomation, but it works!

# USAGE:
snaferrous [OPTIONS]

Options:
  -o, --outfile <OUTFILE>  path to save output file Defaults to not saving output.
      --threads <THREADS>  number of threads to use, default to 10. 
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

