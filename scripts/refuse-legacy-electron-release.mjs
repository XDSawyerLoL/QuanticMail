// This deliberately refuses all production packaging of the retired
// Electron hosted-Web shell. The Windows Alpha native installer is built
// via the separately audited portable native-vault workflow.
process.stderr.write('QUANTIC_NATIVE_ONLY: ancien installateur Electron/Web interdit. Utiliser le paquet Windows natif Quantic Sillage Alpha avec manifest SHA256 et signature Authenticode validée. Aucune publication effectuée.\n');
process.exitCode=1;
