# Pubky Chromium

> [!WARNING]
> Pubky Chromium is for development and experimentation only. It is not ready
> for production use. Do not rely on it for everyday browsing or sensitive data.

Chromium with strict PKDNS DNS-over-HTTPS defaults and native RFC 7250
raw-public-key TLS for Ed25519 public-key URLs.

**[Why Pubky Chromium? Discover the public-key web →](pubky/about/README.md)**

See [Pubky build and usage instructions](pubky/README.md) and
[verification results](pubky/VERIFICATION.md). The custom branch is `pubky`;
Chromium updates are merged from the `upstream` remote.

---

# ![Logo](chrome/app/theme/chromium/product_logo_64.png) Chromium

Chromium is an open-source browser project that aims to build a safer, faster,
and more stable way for all users to experience the web.

The project's web site is https://www.chromium.org.

To check out the source code locally, don't use `git clone`! Instead,
follow [the instructions on how to get the code](docs/get_the_code.md).

Documentation in the source is rooted in [docs/README.md](docs/README.md).

Learn how to [Get Around the Chromium Source Code Directory
Structure](https://www.chromium.org/developers/how-tos/getting-around-the-chrome-source-code).

For historical reasons, there are some small top level directories. Now the
guidance is that new top level directories are for product (e.g. Chrome,
Android WebView, Ash). Even if these products have multiple executables, the
code should be in subdirectories of the product.

If you found a bug, please file it at https://crbug.com/new.
