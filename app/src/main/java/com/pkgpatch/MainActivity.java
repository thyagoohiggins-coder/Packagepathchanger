package com.pkgpatch;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;
import com.pkgpatch.core.ApkSet;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MainActivity extends Activity {
    private static final int PICK = 1;
    private static final String ACTION = "com.pkgpatch.INSTALL_RESULT";
    private TextView log;
    private EditText pkgField;
    private CheckBox authBox;
    private Button pickBtn, appBtn, goBtn;
    private ApkSet input;

    private static final class AppItem {
        final String label, pkg;
        AppItem(String label, String pkg) { this.label = label; this.pkg = pkg; }
        @Override public String toString() { return label + "\n" + pkg; }
    }

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad * 2, pad, pad);
        appBtn = new Button(this); appBtn.setText("Escolher app instalado");
        pickBtn = new Button(this); pickBtn.setText("Escolher APK / APKs / XAPK");
        pkgField = new EditText(this); pkgField.setHint("Novo nome do pacote");
        pkgField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        authBox = new CheckBox(this); authBox.setChecked(true);
        authBox.setText("Ajustar authorities e permissões customizadas");
        goBtn = new Button(this); goBtn.setText("Modificar e instalar"); goBtn.setEnabled(false);
        log = new TextView(this);
        root.addView(appBtn); root.addView(pickBtn); root.addView(pkgField); root.addView(authBox); root.addView(goBtn);
        ScrollView sv = new ScrollView(this); sv.addView(log);
        root.addView(sv);
        setContentView(root);

        appBtn.setOnClickListener(v -> pickInstalledApp());
        pickBtn.setOnClickListener(v -> {
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            i.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
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

    private void pickInstalledApp() {
        say("Carregando apps...");
        new Thread(() -> {
            PackageManager pm = getPackageManager();
            Intent q = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
            List<ResolveInfo> ris = pm.queryIntentActivities(q, 0);
            Set<String> seen = new HashSet<>();
            List<AppItem> apps = new ArrayList<>();
            for (ResolveInfo ri : ris) {
                String p = ri.activityInfo.packageName;
                if (p.equals(getPackageName()) || !seen.add(p)) continue;
                apps.add(new AppItem(String.valueOf(ri.activityInfo.applicationInfo.loadLabel(pm)), p));
            }
            Collections.sort(apps, (x, y) -> x.label.compareToIgnoreCase(y.label));
            runOnUiThread(() -> showAppDialog(apps));
        }).start();
    }

    private void showAppDialog(List<AppItem> apps) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        EditText search = new EditText(this);
        search.setHint("Buscar (ex.: Chrome, Gmail)");
        search.setSingleLine(true);
        ListView lv = new ListView(this);
        ArrayAdapter<AppItem> ad = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, new ArrayList<>(apps));
        lv.setAdapter(ad);
        box.addView(search);
        box.addView(lv, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,
                (int) (getResources().getDisplayMetrics().heightPixels * 0.6)));
        AlertDialog dlg = new AlertDialog.Builder(this).setTitle("Apps instalados").setView(box)
                .setNegativeButton("Cancelar", null).create();
        search.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            public void onTextChanged(CharSequence s, int a, int b, int c) {}
            public void afterTextChanged(Editable s) {
                String t = s.toString().trim().toLowerCase();
                ad.clear();
                for (AppItem it : apps)
                    if (t.isEmpty() || it.label.toLowerCase().contains(t) || it.pkg.toLowerCase().contains(t)) ad.add(it);
            }
        });
        lv.setOnItemClickListener((parent, view, pos, id) -> { dlg.dismiss(); loadInstalled(ad.getItem(pos)); });
        dlg.show();
        say("");
    }

    private void loadInstalled(AppItem app) {
        say("Copiando " + app.label + "...");
        goBtn.setEnabled(false);
        new Thread(() -> {
            try {
                ApplicationInfo ai = getPackageManager().getApplicationInfo(app.pkg, 0);
                List<String> paths = new ArrayList<>();
                paths.add(ai.sourceDir);
                if (ai.splitSourceDirs != null) Collections.addAll(paths, ai.splitSourceDirs);
                File dir = freshDir("in");
                List<File> files = new ArrayList<>();
                for (String p : paths) {
                    File src = new File(p);
                    File dst = new File(dir, files.size() + "_" + src.getName());
                    try (InputStream in = new FileInputStream(src)) { copy(in, dst); }
                    files.add(dst);
                }
                loaded(ApkSet.of(files));
            } catch (Throwable t) { say("Erro: " + t); }
        }).start();
    }

    @Override protected void onActivityResult(int req, int res, Intent data) {
        if (req != PICK || res != RESULT_OK || data == null) return;
        final List<Uri> uris = new ArrayList<>();
        ClipData cd = data.getClipData();
        if (cd != null) for (int i = 0; i < cd.getItemCount(); i++) uris.add(cd.getItemAt(i).getUri());
        else if (data.getData() != null) uris.add(data.getData());
        if (uris.isEmpty()) return;
        say("Lendo arquivo(s)...");
        goBtn.setEnabled(false);
        new Thread(() -> {
            try {
                File dir = freshDir("in");
                List<File> files = new ArrayList<>();
                int i = 0;
                for (Uri u : uris) {
                    File f = new File(dir, "pick" + (i++) + ".zip");
                    try (InputStream in = getContentResolver().openInputStream(u)) { copy(in, f); }
                    files.addAll(ApkSet.expand(f, dir));
                }
                loaded(ApkSet.of(files));
            } catch (Throwable t) { say("Erro: " + t); }
        }).start();
    }

    private void loaded(ApkSet set) {
        input = set;
        runOnUiThread(() -> {
            pkgField.setText(set.packageName + ".clone");
            goBtn.setEnabled(true);
            log.setText("Pacote original: " + set.packageName + "\nAPKs: 1 base + " + set.splits.size() + " split(s)");
        });
    }

    private void run() {
        final String np = pkgField.getText().toString().trim();
        if (!np.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")) { say("Nome de pacote inválido."); return; }
        if (input == null) { say("Escolha um app ou APK primeiro."); return; }
        if (Build.VERSION.SDK_INT >= 26 && !getPackageManager().canRequestPackageInstalls()) {
            startActivity(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + getPackageName())));
            say("Permita a instalação de apps desta fonte e toque novamente.");
            return;
        }
        final boolean auth = authBox.isChecked();
        final ApkSet set = input;
        setBusy(true);
        say("Modificando e assinando " + set.all().size() + " APK(s)...");
        new Thread(() -> {
            try {
                List<File> out = set.repack(freshDir("out"), np, auth, new AndroidKeystoreKey());
                say("APK(s) gerado(s). Instalando...");
                install(out);
            } catch (Throwable t) { say("Erro: " + t); }
            runOnUiThread(() -> setBusy(false));
        }).start();
    }

    private void setBusy(boolean busy) {
        goBtn.setEnabled(!busy); appBtn.setEnabled(!busy); pickBtn.setEnabled(!busy);
    }

    private void install(List<File> apks) throws Exception {
        PackageInstaller pi = getPackageManager().getPackageInstaller();
        PackageInstaller.SessionParams p = new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
        long total = 0;
        for (File f : apks) total += f.length();
        p.setSize(total);
        int id = pi.createSession(p);
        try (PackageInstaller.Session s = pi.openSession(id)) {
            int i = 0;
            for (File apk : apks) {
                try (FileInputStream in = new FileInputStream(apk);
                     OutputStream o = s.openWrite((i++) + ".apk", 0, apk.length())) {
                    byte[] buf = new byte[65536]; int n;
                    while ((n = in.read(buf)) > 0) o.write(buf, 0, n);
                    s.fsync(o);
                }
            }
            Intent cb = new Intent(ACTION).setPackage(getPackageName());
            int flags = PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 31 ? PendingIntent.FLAG_MUTABLE : 0);
            s.commit(PendingIntent.getBroadcast(this, id, cb, flags).getIntentSender());
        }
    }

    private File freshDir(String name) {
        File d = new File(getCacheDir(), name);
        File[] old = d.listFiles();
        if (old != null) for (File f : old) f.delete();
        d.mkdirs();
        return d;
    }

    private static void copy(InputStream in, File dst) throws Exception {
        try (OutputStream o = new FileOutputStream(dst)) {
            byte[] buf = new byte[65536]; int n;
            while ((n = in.read(buf)) > 0) o.write(buf, 0, n);
        }
    }

    private void say(final String m) { runOnUiThread(() -> log.setText(m)); }
}
