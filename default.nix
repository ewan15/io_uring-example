{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  # buildInputs is for dependencies you'd need "at run time",
  # were you to to use nix-build not nix-shell and build whatever you were working on
  buildInputs = [
    pkgs.linuxHeaders
    pkgs.glibc
    pkgs.clang
    pkgs.liburing
  ];
  LD_LIBRARY_PATH = "${pkgs.lib.makeLibraryPath [ pkgs.liburing ] }";
}

