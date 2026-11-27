fn main() {
    #[cfg(windows)]
    {
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("band.ico");
        resource.set("ProductName", "Anyinstaller Stub");
        resource.set("FileDescription", "Anyinstaller Stub");
        resource
            .compile()
            .expect("failed to embed Windows resources");
    }
}
