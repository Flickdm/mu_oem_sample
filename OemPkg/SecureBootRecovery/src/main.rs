#![no_main]
#![no_std]

use uefi::cstr16;
use uefi::prelude::{entry, Boot, Handle, Status, SystemTable};
use uefi::table::runtime::{VariableAttributes, VariableVendor};

const DB_UPDATE_PAYLOAD: &[u8] = include_bytes!("../Payloads/DBUpdate.bin");

#[entry]
fn main(_image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    let mut result = uefi_services::init(&mut system_table);
    if let Err(_) = result {
        // We can't print anything here, because the system table is not initialized yet.
        return Status::LOAD_ERROR;
    }
    
    // clear the screen
    result = system_table
        .stdout()
        .clear();
    if let Err(_) = result {
        // We can't print anything here, otherwise clear would have worked.
        return Status::LOAD_ERROR;
    }

    // print a message
    result = system_table.stdout().output_string(
        cstr16!("\n\n\tAttempting Secure Boot Recovery\n")
    );
    if let Err(_) = result {
        // We can't print anything here, otherwise write would have worked.
        return Status::LOAD_ERROR;
    }
   
    let attributes = VariableAttributes::NON_VOLATILE
        | VariableAttributes::BOOTSERVICE_ACCESS
        | VariableAttributes::RUNTIME_ACCESS
        | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS
        | VariableAttributes::APPEND_WRITE;
    let image_security_db = VariableVendor::IMAGE_SECURITY_DATABASE;
    result = system_table.runtime_services().set_variable(
        cstr16!("db"),
        &image_security_db,
        attributes,
        DB_UPDATE_PAYLOAD);

    if let Err(_) = result {
        system_table.stdout().output_string(
            cstr16!("\n\n\tFailed to update the DB\n")
        ).unwrap();
        system_table.boot_services().stall(5_000_000);
        return Status::LOAD_ERROR;
    }

    // print a message
    system_table.stdout().output_string(
        cstr16!("\n\n\tAppend was successful\n")
    ).unwrap();
    system_table.boot_services().stall(5_000_000);

    Status::SUCCESS
}
