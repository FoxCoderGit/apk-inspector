"""Generate a tiny metadata-only ZIP for browser smoke checks, not an installable app."""
from pathlib import Path
import zipfile

destination = Path(__file__).with_name('sample.zip')
with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
    archive.writestr('AndroidManifest.xml', '''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="org.example.inspector" android:versionName="1.0">
        <uses-permission android:name="android.permission.INTERNET"/>
        <uses-permission android:name="android.permission.READ_CONTACTS"/>
        <application android:label="Synthetic fixture">
            <activity android:name=".MainActivity" android:exported="true"/>
        </application>
    </manifest>''')
    archive.writestr('assets/example.txt', 'Synthetic fixture endpoint: https://example.invalid/demo')
print(destination)
