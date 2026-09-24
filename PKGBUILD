# Maintainer: Efe Tan <efetan@example.com>
pkgname=envlock
pkgver=0.1.0
pkgrel=1
pkgdesc="Secure zero-file environment variable manager with RAM caching daemon"
arch=('x86_64')
url="https://github.com/RaidenEi-20/envlock"
license=('MIT')
depends=('gcc-libs')
makedepends=('cargo')
source=("$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
    cd "$pkgname-$pkgver"
    cargo build --release --locked
}

package() {
    cd "$pkgname-$pkgver"
    install -Dm755 "target/release/$pkgname" "$pkgdir/usr/bin/$pkgname"
}
