using System.IO;
using System.Windows;
using Microsoft.Win32;

namespace Phrasia;

/// <summary>Importing items from KeePass (.kdbx / XML) and CSV exports of other password managers.</summary>
public partial class MainWindow
{
    /// <summary>Unlocked vault: imports items from a KeePass database or an XML / CSV export.</summary>
    private async void ImportKeePass_Click(object sender, RoutedEventArgs e)
    {
        if (_vault is null || IsVaultBusy) return;
        var pick = new OpenFileDialog
        {
            Title = "Import from KeePass or another password manager",
            Filter = "All supported (*.kdbx;*.xml;*.csv)|*.kdbx;*.xml;*.csv|" +
                     "KeePass database (*.kdbx)|*.kdbx|" +
                     "KeePass XML export (*.xml)|*.xml|" +
                     "CSV export – KeePass, KeePassXC, Bitwarden, Proton Pass, browsers (*.csv)|*.csv|" +
                     "All files (*.*)|*.*",
        };
        if (pick.ShowDialog(this) != true) return;
        string path = pick.FileName;

        ImportFileKind kind;
        try
        {
            kind = KeePassImporter.IsKdbxFile(path) ? ImportFileKind.Kdbx
                 : Path.GetExtension(path).Equals(".xml", StringComparison.OrdinalIgnoreCase) ? ImportFileKind.KeePassXml
                 : ImportFileKind.Csv;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ShowEntryStatus("Could not open the file: " + ex.Message, error: true);
            return;
        }
        if (Path.GetFullPath(path).Equals(Path.GetFullPath(_vault.FilePath), StringComparison.OrdinalIgnoreCase))
        {
            ShowEntryStatus("This is your Phrasia vault – use “Import items from backup…” for Phrasia backups.", error: true);
            return;
        }

        var dlg = new KeePassImportDialog(this, path, kind);
        if (dlg.ShowDialog() != true) return;
        string? password = dlg.Password, keyFile = dlg.KeyFilePath;
        var options = dlg.Options;
        bool deleteSource = dlg.DeleteSourceAfterImport;

        ShowEntryStatus(kind == ImportFileKind.Kdbx
            ? "Opening the KeePass database… (key derivation can take a few seconds)"
            : "Reading the export…");
        ImportResult result;
        try
        {
            result = await RunVaultOperationAsync(() => kind switch
            {
                ImportFileKind.Kdbx => KeePassImporter.ReadKdbx(path, password, keyFile, options),
                ImportFileKind.KeePassXml => KeePassImporter.ReadKeePassXml(path, options),
                _ => KeePassImporter.ReadCsv(path, options),
            });
        }
        catch (KeePassWrongKeyException)
        {
            // not the Phrasia master password – it does not count toward the unlock throttle
            Log.Info("KeePass import: wrong password or key file");
            ShowEntryStatus("The KeePass password or key file is wrong – nothing was imported.", error: true);
            return;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException
                                      or FormatException or ArgumentException or OutOfMemoryException)
        {
            Log.Warn("Import failed: {Error}", ex.Message);
            AppMessageBox.Show(this, ex.Message, "Import failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            ShowEntryStatus("Nothing was imported.", error: true);
            return;
        }

        if (_vault is null) return; // the vault locked meanwhile – the decrypted items are simply dropped
        int found = result.Entries.Count;
        int duplicates = KeePassImporter.RemoveExisting(_vault.Entries, result.Entries);

        var summary = new List<string> { $"Source: {result.Source}", $"Items found: {found}" };
        if (duplicates > 0) summary.Add($"Already in your vault (skipped): {duplicates}");
        if (result.RecycleBinSkipped > 0) summary.Add($"In the KeePass recycle bin (not imported): {result.RecycleBinSkipped}");
        if (result.EmptySkipped > 0) summary.Add($"Empty items/rows (skipped): {result.EmptySkipped}");
        if (result.AttachmentsSkipped > 0) summary.Add($"Attachments (not imported, names kept in the note): {result.AttachmentsSkipped}");

        if (result.Entries.Count == 0)
        {
            AppMessageBox.Show(this, string.Join("\n", summary) + "\n\nThere is nothing new to import.",
                "Import", MessageBoxButton.OK, MessageBoxImage.Information);
            ShowEntryStatus("Nothing new to import.");
            OfferSourceDeletion(path, deleteSource);
            return;
        }

        var answer = AppMessageBox.Show(this,
            string.Join("\n", summary) + $"\n\nAdd {result.Entries.Count} new item{(result.Entries.Count == 1 ? "" : "s")} to your vault?",
            "Import", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.Yes);
        if (answer != MessageBoxResult.Yes || _vault is null)
        {
            ShowEntryStatus("Import cancelled – nothing was added.");
            return;
        }

        var (added, _, _) = _vault.Merge(result.Entries);
        if (!TrySaveVault())
        {
            // keep the in-memory vault consistent with the file on disk
            var ids = result.Entries.Select(x => x.Id).ToHashSet();
            _vault.Entries.RemoveAll(x => ids.Contains(x.Id));
            RefreshList(_editing);
            return;
        }
        Log.Info("Imported {Added} items ({Kind}; {Duplicates} duplicates, {Recycle} in recycle bin, {Attachments} attachments skipped)",
            added, kind, duplicates, result.RecycleBinSkipped, result.AttachmentsSkipped);
        SetAttentionFilter(null);
        SearchBox.Text = "";
        RefreshList(_editing);
        ShowEntryStatus($"Imported {added} item{(added == 1 ? "" : "s")} ✓ – run Analyze to check them.");
        OfferSourceDeletion(path, deleteSource);
    }

    /// <summary>Securely deletes a plain-text export (if the user chose it in the import dialog).</summary>
    private void OfferSourceDeletion(string path, bool delete)
    {
        if (!delete) return;
        try
        {
            Vault.SecureDeleteFile(path);
            Log.Info("Plain-text export securely deleted after import");
            ShowEntryStatus("The export file was overwritten and deleted ✓");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log.Warn("Could not delete the export file: {Error}", ex.Message);
            AppMessageBox.Show(this,
                "The export file could not be deleted:\n" + ex.Message +
                "\n\nIt still contains your passwords in plain text – delete it yourself (and empty the Recycle Bin).",
                "Delete export file", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
