{ pkgs ? import <nixpkgs> { } }:

pkgs.stdenv.mkDerivation rec {
  pname = "tegrarcm";
  version = "1.9";

  src = pkgs.lib.cleanSource ./.;

  propagatedBuildInputs = with pkgs; [ cryptopp libusb1 ];

  nativeBuildInputs = with pkgs; [ automake autoconf pkg-config ];
  
  configurePhase = ''
      runHook preConfigure
      ./autogen.sh
      runHook postConfigure
  '';
  
  installPhase = ''
      runHook preInstall
      mkdir -p $out/bin
      cp -a src/tegrarcm $out/bin/
      runHook postInstall
  '';

  meta = with pkgs.lib; {
    description = "Tool to send code to a Tegra device in recovery mode.";
    homepage = "https://github.com/NVIDIA/tegrarcm";
    license = licenses.asl20;
    maintainers = [ ];
  };
}
