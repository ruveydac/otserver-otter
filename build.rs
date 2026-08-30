fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut resource = winresource::WindowsResource::new();
        resource
            .set("CompanyName", "OTserver")
            .set("FileDescription", "Read-only OT discovery for OTserver")
            .set("InternalName", "otserver-otter")
            .set("OriginalFilename", "otserver-otter.exe")
            .set("ProductName", "OTserver Otter")
            .compile()
            .expect("failed to compile Windows executable metadata");
    }
}
