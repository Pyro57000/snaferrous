use clap::Parser;
use std::fmt::Debug;
use std::fs;
use std::fs::read_to_string;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::process::exit;
use std::process::Command;
use colored::Colorize;
use tokio;
use tokio::sync::mpsc::{channel, Sender};

/*
Author: Kevin (Kaged Pyro) Gunter
Purpose: I got tired of snaffler getting caught, so I rewrote it in rust, which edrs have trouble detecting.

*/

/*#[derive(Parser, Debug)]
#[command(version, about, long_about = Some("finds shares, but its written in rust which sometimes gets past EDR!"))]
struct Args{
    #[arg(short, long, help = "path to save output file Defaults to not saving output.")]
    outfile: Option<PathBuf>,

    #[arg(short, long, help = "number of threads to use, default to 10. \nNote thre thread count will be doubled, one set for share finder tasks, and one set for file and infor finding tasks.")]
    threads: Option<usize>,

    #[arg(short, long, help = "specific targets. should be comma separated.")]
    targets: Option<String>,
}*/

#[derive(Parser, Debug)]
#[command(version, about, long_about = Some("finds shares, but its written in rust which sometimes gets past EDR!"))]
struct Args{
    #[arg(short, long, help = "path to save output file Defaults to not saving output.")]
    outfile: Option<PathBuf>,

    #[arg(long, help = "number of threads to use, default to 10.")]
    threads: Option<usize>,

    #[arg(short, long, help = "specific targets. should be comma separated.")]
    targets: Option<String>,

    #[arg(short, long, help = "echo all found files to the console, regardless of keyword matching. (all files will still be saved to the log file)")]
    verbose: bool,
}

#[derive(Clone)]
struct FinderTask{
    id: usize,
    target: String,
    tasktype: TaskType,
}

#[derive(Clone)]
struct Finding{
    path: String,
    keyword: Option<bool>
}

struct Message{
    source: usize,
    tasktype: TaskType,
    finding: Option<Finding>,
    task_finished: bool,
}

#[derive(Clone)]
enum TaskType{
    Share,
    File,
    Info,
}


async fn task_handler(id: usize, current_task: FinderTask, tx: Sender<Message>){
    match current_task.tasktype{
        TaskType::Share => {
            println!("scanning {}", current_task.target);
            let share_list_res = Command::new("net").arg("view").arg(current_task.target.clone()).arg("/all").output();
            let mut success_string = String::new();
            if share_list_res.is_ok(){
                let output = share_list_res.unwrap();
                if output.stdout.len() > 0{
                    success_string = String::from_utf8_lossy(&output.stdout).to_string();
                }
            }
            if success_string.len() > 0{
                let mut sent_lines = Vec::new();
                for line in success_string.lines(){
                    if line.contains("Disk"){
                        let share_name = line.split_whitespace().collect::<Vec<&str>>()[0];
                        let share_path = format!("\\\\{}\\{}", current_task.target, share_name);
                        if !sent_lines.contains(&share_path){
                            sent_lines.push(share_path.clone());
                            let finding = Finding{path: share_path, keyword: None};
                            let message = Message{source: id, tasktype: TaskType::Share, finding: Some(finding), task_finished: false};
                            tx.send(message).await.unwrap();
                        }
                    }
                }
            }
        }
        TaskType::File => {
            let mut sent_lines = Vec::new();
            for entry_res in walkdir::WalkDir::new(current_task.target.clone()){
                if entry_res.is_ok(){
                    let entry = entry_res.unwrap();
                    let file_path = entry.into_path();
                    if file_path.file_name().is_some(){
                        let file_path_string = file_path.display().to_string();
                        if !sent_lines.contains(&file_path_string){
                            sent_lines.push(file_path_string.clone());
                            let finding = Finding{path: file_path_string, keyword: None};
                            let message = Message{source: id, tasktype: TaskType::File, finding: Some(finding), task_finished: false};
                            tx.send(message).await.unwrap();
                        }
                    }
                }
            }
        }
        TaskType::Info => {
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
            let mut file_content = String::new();
            for extension in &files_to_read{
                if current_task.target.contains(extension){
                    let file_content_res = read_to_string(&current_task.target);
                    if file_content_res.is_ok(){
                        file_content = file_content_res.unwrap();
                    }
                }
            }
            let mut sent_lines = Vec::new();
            for thing in &interesting_info{
                let file_name = current_task.target.clone();
                if file_name.contains(thing) || file_content.contains(thing){
                    let sent_line = format!("keyword {}", file_name);
                    if !sent_lines.contains(&sent_line){
                        sent_lines.push(sent_line);
                        let finding = Finding{path: file_name, keyword: Some(true)};
                        let message = Message{source: id, tasktype: TaskType::Info, finding: Some(finding), task_finished: false};
                        tx.send(message).await.unwrap();
                    }
                }
                else{
                    let sent_line = format!("file {}", file_name);
                    if !sent_lines.contains(&sent_line){
                        sent_lines.push(sent_line);
                        let finding = Finding{path: file_name, keyword: Some(false)};
                        let message = Message{source:id, tasktype: TaskType::Info, finding: Some(finding),task_finished: false};
                        tx.send(message).await.unwrap();
                    }
                }
            }
        }
    }
    let message = Message{source: id, tasktype: TaskType::Share, finding: None, task_finished: true};
    let send_res = tx.send(message).await;
    if send_res.is_ok(){
        send_res.unwrap();
    }
    else{
        println!("{}", send_res.err().unwrap());
    }
}

#[tokio::main]
async fn main(){
    let args = Args::parse();
    let mut outfile = PathBuf::new();
    let mut threads = 10;
    let mut save = false;
    let mut computers = Vec::new();
    if args.outfile.is_some(){
        outfile = args.outfile.unwrap();
        save = true;
    }
    if args.threads.is_some(){
        threads = args.threads.unwrap();
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
                        computers.push(computer_name);
                    }
                }
            }
        }
    }
    let mut tasks = Vec::new();
    let mut id_counter = 0;
    for computer in &computers{
        println!("found {}", computer);
        let new_task = FinderTask{id: id_counter, target: computer.clone(), tasktype: TaskType::Share};
        tasks.push(new_task);
        id_counter += 1;
    }
    println!("computer enumeration finished, starting task finder threads...");
    let (tx, mut rx) = channel(1024);
    let mut running = Vec::new();
    let mut continue_wihtout_save = false;
    loop{
        if running.len() < threads{
            for _i in 0 .. threads{
                if tasks.len() > 0{
                    let task = tasks[0].clone();
                    tasks.remove(0);
                    running.push(task.id.clone());
                    tokio::spawn(task_handler(task.id, task, tx.clone()));
                    if running.len() >= threads{
                        break;
                    }
                }
                else{
                    break;
                }
            }
        }
        if running.len() > 0{
            let rxres = rx.try_recv();
            if rxres.is_ok(){
                let mesage = rxres.unwrap();
                if mesage.task_finished{
                    for index in 0 .. running.len(){
                        if index == running.len(){
                            break;
                        }
                        else{
                            if running[index] == mesage.source{
                                running.remove(index);
                            }
                        }
                    }
                }
                else {
                    let finding = mesage.finding.unwrap();
                    match mesage.tasktype{
                        TaskType::Share => {
                            println!("{} {}", "share found!".green(), finding.path);
                            if save{
                                let open_res = OpenOptions::new().create(true).append(true).open(&outfile);
                                if open_res.is_err(){
                                    if !continue_wihtout_save{
                                        eprintln!("{}", "error opening save file!".red());
                                        eprintln!("{}", open_res.err().unwrap().to_string().red());
                                        let mut proceed = String::new();
                                        println!("continue anyway?");
                                        std::io::stdin().read_line(&mut proceed).unwrap();
                                        if proceed.to_lowercase().contains("y"){
                                            continue_wihtout_save = true;
                                        }
                                        else{
                                            exit(1);
                                        }
                                    }
                                }
                                else{
                                    let mut save_file = open_res.unwrap();
                                    let write_res = write!(save_file,"share found! {}\n", finding.path);
                                    if write_res.is_err(){
                                        if !continue_wihtout_save{
                                            eprintln!("{}", "error writing to save file!".red());
                                            eprintln!("{}", write_res.err().unwrap().to_string().red());
                                            let mut proceed = String::new();
                                            println!("proceed without saving?");
                                            std::io::stdin().read_line(&mut proceed).unwrap();
                                            if proceed.to_lowercase().contains("y"){
                                                continue_wihtout_save = true;
                                            }
                                            else{
                                                exit(1);
                                            }
                                        }
                                    }
                                    else{
                                        write_res.unwrap();
                                    }
                                }
                            }
                            let new_task = FinderTask{id: id_counter, tasktype: TaskType::File, target: finding.path};
                            tasks.push(new_task);
                            id_counter += 1;
                        }
                        TaskType::File => {
                            let new_task = FinderTask{id: id_counter, tasktype: TaskType::Info, target: finding.path};
                            tasks.push(new_task);
                            id_counter += 1;
                        }
                        TaskType::Info => {
                            if finding.keyword.unwrap(){
                                println!("{} {}", "keyword match at".green(), finding.path.green());
                                if save{
                                    let open_res = OpenOptions::new().create(true).append(true).open(&outfile);
                                    if open_res.is_err(){
                                        if !continue_wihtout_save{
                                            eprintln!("{}", "error opening save file!".red());
                                            eprintln!("{}", open_res.err().unwrap().to_string().red());
                                            let mut proceed = String::new();
                                            println!("continue anyway?");
                                            std::io::stdin().read_line(&mut proceed).unwrap();
                                            if proceed.to_lowercase().contains("y"){
                                                continue_wihtout_save = true;
                                            }
                                            else{
                                                exit(1);
                                            }
                                        }
                                    }
                                    else{
                                        let mut save_file = open_res.unwrap();
                                        let write_res = write!(save_file,"keyword match at {}\n", finding.path);
                                        if write_res.is_err(){
                                            if !continue_wihtout_save{
                                                eprintln!("{}", "error writing to save file!".red());
                                                eprintln!("{}", write_res.err().unwrap().to_string().red());
                                                let mut proceed = String::new();
                                                println!("proceed without saving?");
                                                std::io::stdin().read_line(&mut proceed).unwrap();
                                                if proceed.to_lowercase().contains("y"){
                                                    continue_wihtout_save = true;
                                                }
                                                else{
                                                    exit(1);
                                                }
                                            }
                                        }
                                        else{
                                            write_res.unwrap();
                                        }
                                    }
                                }
                            }
                            else{
                                if args.verbose{
                                    println!("{} {}", "file found at".green(), finding.path.green());
                                }
                                if save{
                                    let open_res = OpenOptions::new().create(true).append(true).open(&outfile);
                                    if open_res.is_err(){
                                        if !continue_wihtout_save{
                                            eprintln!("{}", "error opening save file!".red());
                                            eprintln!("{}", open_res.err().unwrap().to_string().red());
                                            let mut proceed = String::new();
                                            println!("continue anyway?");
                                            std::io::stdin().read_line(&mut proceed).unwrap();
                                            if proceed.to_lowercase().contains("y"){
                                                continue_wihtout_save = true;
                                            }
                                            else{
                                                exit(1);
                                            }
                                        }
                                    }
                                    else{
                                        let mut save_file = open_res.unwrap();
                                        let write_res = write!(save_file,"file found! {}\n", finding.path);
                                        if write_res.is_err(){
                                            if !continue_wihtout_save{
                                                eprintln!("{}", "error writing to save file!".red());
                                                eprintln!("{}", write_res.err().unwrap().to_string().red());
                                                let mut proceed = String::new();
                                                println!("proceed without saving?");
                                                std::io::stdin().read_line(&mut proceed).unwrap();
                                                if proceed.to_lowercase().contains("y"){
                                                    continue_wihtout_save = true;
                                                }
                                                else{
                                                    exit(1);
                                                }
                                            }
                                        }
                                        else{
                                            write_res.unwrap();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if running.len() == 0 && tasks.len() == 0 && rx.is_empty(){
            break;
        }
    }
}