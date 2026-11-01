package com.pkgpatch;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageInstaller;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import com.pkgpatch.core.ApkRepacker;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class MainActivity extends Activity {
    private static final int PICK = 1;
    private static final String ACTION = "com.pkgpatch.INSTALL_RESULT";
    private TextView log;
    private EditText pkgField;
    private CheckBox authBox;
    private Button pickBtn, goBtn;
    private File input;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad * 2, pad, pad);
        pickBtn = new Button(this); pickBtn.setText("Escolher APK");
        pkgField = new EditText(this); pkgField.setHint("Novo nome do pacote");
        pkgField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        authBox = new CheckBox(this); authBox.setChecked(true);
        authBox.setText("Ajustar authorities e permissões customizadas");
        goBtn = new Button(this); goBtn.setText("Modificar e instalar"); goBtn.setEnabled(false);
        log = new TextView(this);
        root.addView(pickBtn); root.addView(pkgField); root.addView(authBox); root.addView(goBtn);
        ScrollView sv = new ScrollView(this); sv.addView(log);
        root.addView(sv);
        setContentView(root);

        pickBtn.setOnClickListener(v -> {
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            startActivityForResult(i, PICK);
        });
        goBtn.setOnClickListener(v -> run());

        IntentFilter f = new IntentFilter(ACTION);
        BroadcastReceiver r = new BroadcastReceiver() {
            @Override public void onReceive(Context c, Intent in) {
                int st = in.getIntExtra(PackageInstaller.EXTRA_STATUS, -1);
                if (st == PackageInstaller.STATUS_PENDING_USER_ACTION) {
                    Intent confirm = in.getParcelableExtra(Intent.EXTRA_INTENT);
                    if (confirm != null) { confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK); startActivity(confirm); }
                } else if (st == PackageInstaller.STATUS_SUCCESS) {
                    say("Instalado com sucesso.");
                } else {
                    say("Falha na instalação: " + in.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE));
                }
            }
        };
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(r, f, Context.RECEIVER_NOT_EXPORTED);
        else registerReceiver(r, f);
    }

    @Override protected void onActivityResult(int req, int res, Intent data) {
        if (req != PICK || res != RESULT_OK || data == null) return;
        final Uri uri = data.getData();
        say("Lendo APK...");
        new Thread(() -> {
            try {
                File f = new File(getCacheDir(), "input.apk");
                try (InputStream in = getContentResolver().openInputStream(uri); OutputStream o = new FileOutputStream(f)) {
                    byte[] buf = new byte[65536]; int n;
                    while ((n = in.read(buf)) > 0) o.write(buf, 0, n);
                }
                final String pkg = ApkRepacker.readPackage(f);
                input = f;
                runOnUiThread(() -> {
                    pkgField.setText(pkg + ".clone");
                    goBtn.setEnabled(true);
                    log.setText("Pacote original: " + pkg);
                });
            } catch (Throwable t) { say("Erro: " + t); }
        }).start();
    }

    private void run() {
        final String np = pkgField.getText().toString().trim();
        if (!np.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")) { say("Nome de pacote inválido."); return; }
        if (Build.VERSION.SDK_INT >= 26 && !getPackageManager().canRequestPackageInstalls()) {
            startActivity(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + getPackageName())));
            say("Permita a instalação de apps desta fonte e toque novamente.");
            return;
        }
        final boolean auth = authBox.isChecked();
        goBtn.setEnabled(false);
        say("Modificando e assinando...");
        new Thread(() -> {
            try {
                File out = new File(getCacheDir(), "output.apk");
                ApkRepacker.repack(input, out, np, auth, new AndroidKeystoreKey());
                say("APK gerado. Instalando...");
                install(out);
            } catch (Throwable t) { say("Erro: " + t); }
            runOnUiThread(() -> goBtn.setEnabled(true));
        }).start();
    }

    private void install(File apk) throws Exception {
        PackageInstaller pi = getPackageManager().getPackageInstaller();
        PackageInstaller.SessionParams p = new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
        int id = pi.createSession(p);
        try (PackageInstaller.Session s = pi.openSession(id);
             java.io.FileInputStream in = new java.io.FileInputStream(apk);
             OutputStream o = s.openWrite("app.apk", 0, apk.length())) {
            byte[] buf = new byte[65536]; int n;
            while ((n = in.read(buf)) > 0) o.write(buf, 0, n);
            s.fsync(o);
            Intent cb = new Intent(ACTION).setPackage(getPackageName());
            int flags = PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 31 ? PendingIntent.FLAG_MUTABLE : 0);
            s.commit(PendingIntent.getBroadcast(this, id, cb, flags).getIntentSender());
        }
    }

    private void say(final String m) { runOnUiThread(() -> log.setText(m)); }
}
