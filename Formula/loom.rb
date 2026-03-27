# Formula/loom.rb
#
# Homebrew formula for Loom — gRPC L7 Debugging Proxy.
#
# This file lives in the homebrew-tap repo at:
#   https://github.com/joshuabvarghese/homebrew-tap
#
# Users install via:
#   brew install joshuabvarghese/tap/loom
#
# GoReleaser auto-updates this file on every tagged release.
# To update manually:
#   1. sha256sum loom_darwin_arm64.tar.gz  (and other platforms)
#   2. Update sha256 values and version
#   3. Commit to joshuabvarghese/homebrew-tap

class Loom < Formula
  desc "gRPC L7 debugging proxy — intercept, decode and mutate gRPC calls in real-time"
  homepage "https://github.com/joshuabvarghese/loom"
  version "0.1.0"
  license "MIT"

  # ── macOS ──────────────────────────────────────────────────────────────────
  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/joshuabvarghese/loom/releases/download/v#{version}/loom_darwin_arm64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_OF_loom_darwin_arm64.tar.gz"
    else
      url "https://github.com/joshuabvarghese/loom/releases/download/v#{version}/loom_darwin_amd64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_OF_loom_darwin_amd64.tar.gz"
    end
  end

  # ── Linux ──────────────────────────────────────────────────────────────────
  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/joshuabvarghese/loom/releases/download/v#{version}/loom_linux_arm64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_OF_loom_linux_arm64.tar.gz"
    else
      url "https://github.com/joshuabvarghese/loom/releases/download/v#{version}/loom_linux_amd64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_OF_loom_linux_amd64.tar.gz"
    end
  end

  def install
    bin.install "loom"
  end

  test do
    assert_match "loom v", shell_output("#{bin}/loom -version")
  end
end
