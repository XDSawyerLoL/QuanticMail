/* eslint-disable @typescript-eslint/no-require-imports */
/* Native Quantic Sillage only. The old Electron shell must never open a
 * hosted website or revive browser-custodied keys as an implicit fallback.
 * All sensitive operations remain in the local trusted broker; no renderer.
 */
const {app,dialog}=require('electron');
const {nativeStartupPolicy}=require('./native-entry-policy.cjs');
async function reportAndQuit(type,message,detail,code){
  try{
    await dialog.showMessageBox({
      type,title:'Quantic Sillage · Application native',noLink:true,
      message,detail,buttons:['Fermer'],defaultId:0,cancelId:0
    });
  }catch{/* A missing UI must not restore a remote fallback. */}
  app.exit(code);
}
app.whenReady().then(async()=>{
  let start;
  try{
    start=nativeStartupPolicy(process.argv,{
      platform:process.platform,nodeVersion:process.versions.node,
      tty:process.stderr?.isTTY===true
    });
  }catch{
    await reportAndQuit('error','Démarrage natif refusé',
      'Paramètres ou empreinte de confiance invalides. Aucun client Web de secours.',1);
    return;
  }
  if(start.mode==='windows-native-lab'){
    try{
      const {runWindowsNativeDesktop}=await import('./native-windows-desktop.mjs');
      const status=await runWindowsNativeDesktop(dialog,{
        binary:start.binary,binarySha256:start.binarySha256,dir:start.dir
      });
      app.exit(status==='failed'?1:0);
    }catch{
      await reportAndQuit('error','Coffre Windows indisponible',
        'Aucune identité Web n’a été ouverte ni restaurée automatiquement.',1);
    }
    return;
  }
  if(start.mode==='linux-native-lab'){
    try{
      const {runNativeDesktop}=await import('./native-vault-desktop.mjs');
      const status=await runNativeDesktop(dialog);
      app.exit(status==='failed'?1:0);
    }catch{
      await reportAndQuit('error','Coffre Linux indisponible',
        'Aucun repli vers un navigateur ou une clé Web.',1);
    }
    return;
  }
  await reportAndQuit('warning','Ancien client Web désactivé',
    'Quantic Mail est désormais conçu comme un logiciel local. Pour les essais actuels, utilisez l’installateur Quantic Sillage Alpha natif avec son paquet vérifié. Les anciennes données Web sont conservées pour une migration sécurisée ; aucune bascule automatique n’est autorisée.',2);
}).catch(()=>app.exit(1));
