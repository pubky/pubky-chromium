# Copy to .gclient in the directory containing the src checkout.
solutions = [
    {
        "name": "src",
        "url": "https://github.com/pubky/pubky-chromium.git",
        "managed": False,
        "custom_deps": {},
        "custom_vars": {},
    },
]
target_os = ["mac"]
