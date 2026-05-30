const registerApp = () => {
  Alpine.data("envGuardApp", () => ({
    locked: true,
    vaultExists: true,
    activeView: "unlock",
    password: "",
    confirmPassword: "",
    showUnlockPassword: false,
    errorMsg: "",
    confirmErrorMsg: "",
    vaultDir: "",
    appConfig: {
      theme: "dark",
      default_shell: "powershell",
      launch_at_startup: false,
      start_locked: true,
    },
    profiles: [],
    newProfileName: "",
    selectedProfile: null,
    editingProfileId: null,
    editProfileName: "",
    editProfileDesc: "",
    rulesTimeout: "",
    rulesShells: "",
    newSecretKey: "",
    newSecretValue: "",
    credentials: [],
    editingCredId: null,
    editingCredValue: "",
    activeSessions: [],
    scanDirPath: "",
    scannedFiles: [],
    toasts: [],
    loading: false,
    showConfirm: false,
    confirmTitle: "",
    confirmMsg: "",
    confirmButtonText: "",
    confirmCallback: null,
    bulkEnvInput: "",

    async init() {
      try {
        if (window.__TAURI__ && window.__TAURI__.core) {
          const dir = await window.__TAURI__.core.invoke("get_vault_directory");
          this.vaultDir = dir;
          this.vaultExists = await window.__TAURI__.core.invoke("is_vault_initialized");
        } else {
          this.vaultDir = "Unknown";
        }
      } catch (e) {
        this.vaultDir = "Unknown";
      }

      try {
        if (window.__TAURI__ && window.__TAURI__.core) {
          const config = await window.__TAURI__.core.invoke("get_app_config");
          this.appConfig = config;
          this.applyTheme();
        }
      } catch (e) {}

      window.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "l") {
          e.preventDefault();
          if (!this.locked) {
            this.lock();
          }
        }
      });

      setInterval(() => {
        if (!this.locked) {
          this.syncSessionsQuietly();
        }
      }, 1000);
    },

    applyTheme() {
      if (this.appConfig.theme === "dark") {
        document.body.classList.remove("light-theme");
      } else {
        document.body.classList.add("light-theme");
      }
    },

    async saveConfig() {
      try {
        await window.__TAURI__.core.invoke("save_app_config", { config: this.appConfig });
        this.applyTheme();
      } catch (e) {
        this.showToast("Failed to save config: " + e, "danger");
      }
    },

    async toggleTheme() {
      this.appConfig.theme = this.appConfig.theme === "dark" ? "light" : "dark";
      await this.saveConfig();
    },

    showToast(message, type = "info") {
      const id = Date.now();
      this.toasts.push({ id, message, type });
      setTimeout(() => {
        this.removeToast(id);
      }, 3000);
    },

    removeToast(id) {
      this.toasts = this.toasts.filter(t => t.id !== id);
    },

    confirmDialog(title, msg, buttonText, callback) {
      this.confirmTitle = title;
      this.confirmMsg = msg;
      this.confirmButtonText = buttonText;
      this.confirmCallback = callback;
      this.showConfirm = true;
    },

    executeConfirm() {
      this.showConfirm = false;
      if (this.confirmCallback) {
        this.confirmCallback();
      }
    },

    async unlock() {
      this.errorMsg = "";
      this.confirmErrorMsg = "";
      
      if (!this.password) {
        this.errorMsg = "Password cannot be empty";
        return;
      }
      
      if (!this.vaultExists && this.password !== this.confirmPassword) {
        this.confirmErrorMsg = "Passwords do not match";
        return;
      }

      this.loading = true;
      try {
        await window.__TAURI__.core.invoke("unlock_vault", { password: this.password });
        this.password = "";
        this.confirmPassword = "";
        this.vaultExists = true;
        this.locked = false;
        this.activeView = "profiles";
        await this.loadProfiles();
        await this.loadSessions();
        this.showToast("Vault unlocked successfully", "success");
      } catch (e) {
        this.errorMsg = e;
        this.showToast("Failed to unlock vault: " + e, "danger");
      } finally {
        this.loading = false;
      }
    },

    async lock() {
      this.loading = true;
      try {
        await window.__TAURI__.core.invoke("lock_vault");
        this.locked = true;
        this.profiles = [];
        this.credentials = [];
        this.activeSessions = [];
        this.scannedFiles = [];
        this.selectedProfile = null;
        this.editingCredId = null;
        this.editingCredValue = "";
        this.showToast("Vault locked", "info");
      } catch (e) {
        this.showToast("Error locking vault: " + e, "danger");
      } finally {
        this.loading = false;
      }
    },

    triggerWipeVault() {
      this.confirmDialog(
        "Wipe Vault",
        "This will permanently delete the vault, destroying all profiles and credentials. This action is irreversible.",
        "Wipe",
        async () => {
          this.loading = true;
          try {
            await window.__TAURI__.core.invoke("wipe_vault");
            this.locked = true;
            this.vaultExists = false;
            this.profiles = [];
            this.credentials = [];
            this.activeSessions = [];
            this.scannedFiles = [];
            this.selectedProfile = null;
            this.editingCredId = null;
            this.editingCredValue = "";
            this.showToast("Vault wiped successfully", "success");
          } catch (e) {
            this.showToast("Failed to wipe vault: " + e, "danger");
          } finally {
            this.loading = false;
          }
        }
      );
    },

    async loadProfiles() {
      try {
        const list = await window.__TAURI__.core.invoke("list_profiles");
        this.profiles = list;
      } catch (e) {
        this.showToast("Failed to load profiles", "danger");
      }
    },

    async createProfile() {
      if (!this.newProfileName.trim()) {
        this.showToast("Profile name is required", "danger");
        return;
      }
      this.loading = true;
      try {
        const defaultRules = {
          expiration_seconds: null,
          allowed_shells: [],
          require_auth_on_resume: false
        };
        await window.__TAURI__.core.invoke("create_profile", {
          name: this.newProfileName,
          description: this.newProfileDesc || null,
          rules: defaultRules
        });
        this.newProfileName = "";
        this.newProfileDesc = "";
        await this.loadProfiles();
        this.showToast("Profile created", "success");
      } catch (e) {
        this.showToast("Failed to create profile: " + e, "danger");
      } finally {
        this.loading = false;
      }
    },

    startEditingProfile(p) {
      this.editingProfileId = p.id;
      this.editProfileName = p.name;
      this.editProfileDesc = p.description || "";
    },

    cancelProfileEdit() {
      this.editingProfileId = null;
    },

    async saveProfileEdit() {
      if (!this.editProfileName.trim()) {
        this.showToast("Profile name is required", "danger");
        return;
      }
      this.loading = true;
      try {
        await window.__TAURI__.core.invoke("update_profile", {
          id: this.editingProfileId,
          name: this.editProfileName,
          description: this.editProfileDesc || null
        });
        if (this.selectedProfile && this.selectedProfile.id === this.editingProfileId) {
          this.selectedProfile.name = this.editProfileName;
          this.selectedProfile.description = this.editProfileDesc || null;
        }
        this.editingProfileId = null;
        await this.loadProfiles();
        this.showToast("Profile updated", "success");
      } catch (e) {
        this.showToast("Failed to update profile: " + e, "danger");
      } finally {
        this.loading = false;
      }
    },

    async triggerDuplicateProfile(id) {
      this.loading = true;
      try {
        await window.__TAURI__.core.invoke("duplicate_profile", { id });
        await this.loadProfiles();
        this.showToast("Profile duplicated", "success");
      } catch (e) {
        this.showToast("Failed to duplicate profile: " + e, "danger");
      } finally {
        this.loading = false;
      }
    },

    async selectProfile(id) {
      this.loading = true;
      try {
        const p = await window.__TAURI__.core.invoke("get_profile", { id });
        this.selectedProfile = p;
        this.rulesTimeout = p.session_rules.expiration_seconds !== null ? p.session_rules.expiration_seconds : "";
        this.rulesShells = p.session_rules.allowed_shells.join(", ");
        await this.loadCredentials(id);
        this.activeView = "profile-detail";
      } catch (e) {
        this.showToast("Failed to load profile details", "danger");
      } finally {
        this.loading = false;
      }
    },

    async loadCredentials(profileId) {
      try {
        const list = await window.__TAURI__.core.invoke("list_credentials", { profileId });
        this.credentials = list.map(c => ({
          ...c,
          revealed: false,
          decryptedValue: ""
        }));
      } catch (e) {
        this.showToast("Failed to load credentials", "danger");
      }
    },

    async saveRules() {
      if (!this.selectedProfile) return;
      this.loading = true;
      try {
        const timeout = this.rulesTimeout ? parseInt(this.rulesTimeout, 10) : null;
        const shells = this.rulesShells.split(",").map(s => s.trim()).filter(s => s);
        const rules = {
          expiration_seconds: timeout,
          allowed_shells: shells,
          require_auth_on_resume: false
        };
        await window.__TAURI__.core.invoke("update_profile_rules", {
          id: this.selectedProfile.id,
          rules
        });
        this.showToast("Session rules saved", "success");
      } catch (e) {
        this.showToast("Failed to save rules: " + e, "danger");
      } finally {
        this.loading = false;
      }
    },

    async addSecret() {
      if (!this.selectedProfile) return;
      if (!this.newSecretKey.trim() || !this.newSecretValue) {
        this.showToast("Key and Value are required", "danger");
        return;
      }
      this.loading = true;
      try {
        await window.__TAURI__.core.invoke("add_credential", {
          profileId: this.selectedProfile.id,
          key: this.newSecretKey.trim(),
          value: this.newSecretValue
        });
        this.newSecretKey = "";
        this.newSecretValue = "";
        await this.loadCredentials(this.selectedProfile.id);
        this.showToast("Secret added", "success");
      } catch (e) {
        this.showToast("Failed to add secret: " + e, "danger");
      } finally {
        this.loading = false;
      }
    },

    async handleFileDrop(e) {
      const file = e.dataTransfer.files[0];
      if (file) {
        try {
          const text = await file.text();
          this.bulkEnvInput = text;
          this.showToast("File loaded successfully", "success");
        } catch (err) {
          this.showToast("Failed to read file", "danger");
        }
      }
    },

    async processBulkEnv() {
      if (!this.selectedProfile) return;
      if (!this.bulkEnvInput.trim()) {
        this.showToast("Nothing to import", "danger");
        return;
      }
      this.loading = true;
      try {
        const lines = this.bulkEnvInput.split('\n');
        let count = 0;
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#')) continue;
          
          const match = trimmed.match(/^([^=]+)=(.*)$/);
          if (match) {
            const key = match[1].trim();
            let value = match[2].trim();
            if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
            else if (value.startsWith("'") && value.endsWith("'")) value = value.slice(1, -1);
            
            await window.__TAURI__.core.invoke("add_credential", {
              profileId: this.selectedProfile.id,
              key: key,
              value: value
            });
            count++;
          }
        }
        this.bulkEnvInput = "";
        await this.loadCredentials(this.selectedProfile.id);
        this.showToast(`Successfully imported ${count} secrets`, "success");
      } catch (e) {
        this.showToast("Failed during bulk import: " + e, "danger");
      } finally {
        this.loading = false;
      }
    },

    async toggleSecretReveal(cred) {
      if (cred.revealed) {
        cred.revealed = false;
        cred.decryptedValue = "";
      } else {
        try {
          const val = await window.__TAURI__.core.invoke("decrypt_credential", { credentialId: cred.id });
          cred.decryptedValue = val;
          cred.revealed = true;
        } catch (e) {
          this.showToast("Failed to decrypt secret", "danger");
        }
      }
    },

    async copySecret(id) {
      try {
        const val = await window.__TAURI__.core.invoke("decrypt_credential", { credentialId: id });
        await window.__TAURI__.core.invoke("plugin:clipboard-manager|write_text", { text: val });
        this.showToast("Copied to clipboard (auto-clears in 30s)", "success");
        setTimeout(async () => {
          try {
            await window.__TAURI__.core.invoke("plugin:clipboard-manager|write_text", { text: "" });
            this.showToast("Clipboard cleared", "info");
          } catch (err) {}
        }, 30000);
      } catch (e) {
        this.showToast("Failed to copy: " + e, "danger");
      }
    },

    async startEditing(cred) {
      this.editingCredId = cred.id;
      try {
        const val = await window.__TAURI__.core.invoke("decrypt_credential", { credentialId: cred.id });
        this.editingCredValue = val;
      } catch (e) {
        this.editingCredValue = "";
      }
    },

    async saveCredentialEdit(id) {
      if (!this.editingCredValue) {
        this.showToast("Value is required", "danger");
        return;
      }
      this.loading = true;
      try {
        await window.__TAURI__.core.invoke("update_credential", {
          credentialId: id,
          value: this.editingCredValue
        });
        this.editingCredId = null;
        this.editingCredValue = "";
        await this.loadCredentials(this.selectedProfile.id);
        this.showToast("Secret updated", "success");
      } catch (e) {
        this.showToast("Failed to update secret: " + e, "danger");
      } finally {
        this.loading = false;
      }
    },

    triggerDeleteSecret(cred) {
      this.confirmDialog(
        "Delete Secret",
        `Are you sure you want to delete '${cred.key}'? This cannot be undone.`,
        "Delete",
        async () => {
          this.loading = true;
          try {
            await window.__TAURI__.core.invoke("delete_credential", { credentialId: cred.id });
            await this.loadCredentials(this.selectedProfile.id);
            this.showToast("Secret deleted", "success");
          } catch (e) {
            this.showToast("Failed to delete secret: " + e, "danger");
          } finally {
            this.loading = false;
          }
        }
      );
    },

    triggerDeleteProfile(id) {
      this.confirmDialog(
        "Delete Profile",
        "Are you sure you want to delete this profile? All associated credentials and active sessions will be destroyed.",
        "Delete",
        async () => {
          this.loading = true;
          try {
            await window.__TAURI__.core.invoke("delete_profile", { id });
            this.activeView = "profiles";
            this.selectedProfile = null;
            await this.loadProfiles();
            this.showToast("Profile deleted", "success");
          } catch (e) {
            this.showToast("Failed to delete profile: " + e, "danger");
          } finally {
            this.loading = false;
          }
        }
      );
    },

    async startSession(profileId) {
      this.loading = true;
      try {
        const shell = this.appConfig.default_shell;
        await window.__TAURI__.core.invoke("start_session", { profileId, shell });
        this.showToast("Session injected! Every new terminal session will have these variables (restart your existing terminals).", "success");
        await this.loadSessions();
        this.activeView = "sessions";
      } catch (e) {
        this.showToast("Failed to launch session: " + e, "danger");
      } finally {
        this.loading = false;
      }
    },

    async loadSessions() {
      try {
        const list = await window.__TAURI__.core.invoke("list_active_sessions");
        this.activeSessions = list;
      } catch (e) {
        this.showToast("Failed to load active sessions", "danger");
      }
    },

    async syncSessionsQuietly() {
      try {
        const list = await window.__TAURI__.core.invoke("list_active_sessions");
        this.activeSessions = list;
      } catch (e) {}
    },

    triggerStopSession(id) {
      this.confirmDialog(
        "Terminate Session",
        "Are you sure you want to terminate this session? The underlying shell process will be immediately killed.",
        "Terminate",
        async () => {
          this.loading = true;
          try {
            await window.__TAURI__.core.invoke("stop_session", { sessionId: id });
            await this.loadSessions();
            this.showToast("Session terminated", "success");
          } catch (e) {
            this.showToast("Failed to terminate session: " + e, "danger");
          } finally {
            this.loading = false;
          }
        }
      );
    },

    async scanDirectory() {
      if (!this.scanDirPath.trim()) {
        this.showToast("Directory path is required", "danger");
        return;
      }
      this.loading = true;
      try {
        const list = await window.__TAURI__.core.invoke("scan_for_env_files", { path: this.scanDirPath.trim() });
        this.scannedFiles = list;
        if (list.length === 0) {
          this.showToast("No files found", "info");
        } else {
          this.showToast(`Found ${list.length} files`, "success");
        }
      } catch (e) {
        this.showToast("Scan failed: " + e, "danger");
      } finally {
        this.loading = false;
      }
    },

    async loadSettings() {
      try {
        const dir = await window.__TAURI__.core.invoke("get_vault_directory");
        this.vaultDir = dir;
      } catch (e) {}
    },

    formatShell(shell) {
      if (typeof shell === "string") return shell;
      if (shell.Custom) return `Custom (${shell.Custom})`;
      return Object.keys(shell)[0] || "Unknown";
    },

    formatStatus(status) {
      if (typeof status === "string") return status;
      if (status.Failed) return `Failed: ${status.Failed}`;
      return "Unknown";
    },

    formatTimestamp(ts) {
      try {
        const d = new Date(ts);
        return d.toLocaleString();
      } catch (e) {
        return ts;
      }
    }
  }));
};

if (window.Alpine) {
  registerApp();
} else {
  document.addEventListener("alpine:init", registerApp);
}
