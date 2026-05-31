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
      clipboard_clear_timeout: 30,
    },
    profiles: [],
    newProfileName: "",
    selectedProfile: null,
    editingProfileId: null,
    editProfileName: "",
    editProfileDesc: "",
    editProfileColor: "",
    editProfileTags: "",
    searchQuery: "",
    get filteredProfiles() {
      if (!this.searchQuery.trim()) return this.profiles;
      const q = this.searchQuery.toLowerCase();
      return this.profiles.filter(p => p.name.toLowerCase().includes(q) || (p.description && p.description.toLowerCase().includes(q)) || (p.tags && p.tags.some(t => t.toLowerCase().includes(q))));
    },
    rulesTimeout: "",
    rulesRequireAuth: false,
    rulesShells: "",
    newSecretKey: "",
    newSecretValue: "",
    credentials: [],
    credSearchQuery: "",
    get filteredCredentials() {
      if (!this.credSearchQuery.trim()) return this.credentials;
      const q = this.credSearchQuery.toLowerCase();
      return this.credentials.filter(c => c.key.toLowerCase().includes(q));
    },
    selectedCredIds: [],
    get allSelected() {
      return this.filteredCredentials.length > 0 && this.selectedCredIds.length === this.filteredCredentials.length;
    },
    toggleSelectAll() {
      if (this.allSelected) {
        this.selectedCredIds = [];
      } else {
        this.selectedCredIds = this.filteredCredentials.map(c => c.id);
      }
    },
    toggleSelectCred(id) {
      const idx = this.selectedCredIds.indexOf(id);
      if (idx > -1) {
        this.selectedCredIds.splice(idx, 1);
      } else {
        this.selectedCredIds.push(id);
      }
    },
    editingCredId: null,
    editingCredValue: "",
    editingCredTags: "",
    showGeneratorModal: false,
    showHistoryModal: false,
    credentialHistory: [],
    historyCredId: null,
    generatorLength: 32,
    generatorSymbols: true,
    generatedToken: "",
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

    calculateEntropy(str) {
      if (!str) return 0;
      let charset = 0;
      if (/[a-z]/.test(str)) charset += 26;
      if (/[A-Z]/.test(str)) charset += 26;
      if (/[0-9]/.test(str)) charset += 10;
      if (/[^a-zA-Z0-9]/.test(str)) charset += 32;
      if (charset === 0) return 0;
      return str.length * Math.log2(charset);
    },
    getEntropyColor(entropy) {
      if (entropy < 40) return 'var(--danger-color, #dc3545)';
      if (entropy < 60) return '#e0a800';
      if (entropy < 80) return 'var(--success-color, #28a745)';
      return '#20c997';
    },
    getEntropyLabel(entropy) {
      if (entropy === 0) return '';
      if (entropy < 40) return 'Weak';
      if (entropy < 60) return 'Fair';
      if (entropy < 80) return 'Good';
      return 'Strong';
    },

    showCommandPalette: false,
    paletteSearchQuery: "",
    paletteSelectedIndex: 0,
    previousFocusElement: null,
    get paletteResults() {
      if (!this.paletteSearchQuery.trim()) return [];
      const q = this.paletteSearchQuery.toLowerCase();
      let results = [];
      
      this.profiles.forEach(p => {
        if (p.name.toLowerCase().includes(q) || (p.description && p.description.toLowerCase().includes(q))) {
          results.push({ type: 'profile', text: `Profile: ${p.name}`, icon: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>', action: () => { this.activeView = 'profiles'; this.selectProfile(p.id); } });
        }
      });
      
      const views = ['profiles', 'sessions', 'scanner', 'settings'];
      views.forEach(v => {
        if (v.toLowerCase().includes(q)) {
          results.push({ type: 'view', text: `Navigate: ${v.charAt(0).toUpperCase() + v.slice(1)}`, icon: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>', action: () => { this.activeView = v; } });
        }
      });

      return results.slice(0, 10);
    },
    executePaletteAction() {
      if (this.paletteResults.length > 0 && this.paletteSelectedIndex < this.paletteResults.length) {
        this.paletteResults[this.paletteSelectedIndex].action();
        this.showCommandPalette = false;
        this.paletteSearchQuery = "";
        if (this.previousFocusElement) {
          this.previousFocusElement.focus();
          this.previousFocusElement = null;
        }
      }
    },

    async openVaultDirectory() {
      try {
        await window.__TAURI__.core.invoke("open_vault_directory");
      } catch (e) {
        this.showToast("Failed to open directory: " + e, "danger");
      }
    },

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

      setInterval(() => {
        if (!this.locked) {
          this.syncSessionsQuietly();
        }
      }, 1000);

      window.addEventListener('keydown', (e) => {
        if (e.ctrlKey || e.metaKey) {
          if (e.key.toLowerCase() === 'n') {
            e.preventDefault();
            if (!this.locked) {
              this.activeView = 'profiles';
              document.getElementById('newProfileInput')?.focus();
            }
          } else if (e.key.toLowerCase() === 'l') {
            e.preventDefault();
            if (!this.locked) {
              this.lock();
            }
          } else if (e.key === ',') {
            e.preventDefault();
            if (!this.locked) {
              this.activeView = 'settings';
            }
          } else if (e.key.toLowerCase() === 'k') {
            e.preventDefault();
            if (!this.locked) {
              this.previousFocusElement = document.activeElement;
              this.showCommandPalette = true;
              this.paletteSearchQuery = "";
              this.paletteSelectedIndex = 0;
              setTimeout(() => document.getElementById('paletteSearchInput')?.focus(), 50);
            }
          }
        } else if (e.key === 'Escape') {
          if (this.showCommandPalette) {
            this.showCommandPalette = false;
          }
        }
      });

      if (window.matchMedia) {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
          if (this.appConfig.theme === "system") {
            this.applyTheme();
          }
        });
      }
    },

    applyTheme() {
      let isDark = false;
      if (this.appConfig.theme === "system") {
        isDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      } else {
        isDark = this.appConfig.theme === "dark";
      }

      if (isDark) {
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
        list.sort((a, b) => {
          const tA = a.last_used_at ? new Date(a.last_used_at).getTime() : new Date(a.created_at).getTime();
          const tB = b.last_used_at ? new Date(b.last_used_at).getTime() : new Date(b.created_at).getTime();
          return tB - tA;
        });
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
      this.editProfileColor = p.color || "";
      this.editProfileTags = p.tags ? p.tags.join(", ") : "";
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
        
        const tagsArray = this.editProfileTags.split(",").map(t => t.trim()).filter(t => t.length > 0);
        await window.__TAURI__.core.invoke("update_profile_metadata", {
          id: this.editingProfileId,
          color: this.editProfileColor || null,
          tags: tagsArray
        });

        if (this.selectedProfile && this.selectedProfile.id === this.editingProfileId) {
          this.selectedProfile.name = this.editProfileName;
          this.selectedProfile.description = this.editProfileDesc || null;
          this.selectedProfile.color = this.editProfileColor || null;
          this.selectedProfile.tags = tagsArray;
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
        this.rulesShells = p.session_rules.allowed_shells.map(s => typeof s === 'string' ? s : Object.keys(s)[0]).join(", ");
        this.rulesRequireAuth = p.session_rules.require_auth_on_resume || false;
        await this.loadCredentials(id);
        this.activeView = "profile-detail";
      } catch (e) {
        this.showToast("Failed to load profile details", "danger");
      } finally {
        this.loading = false;
      }
    },

    async loadCredentials(profileId) {
      this.selectedCredIds = [];
      try {
        const list = await window.__TAURI__.core.invoke("list_credentials", { profileId });
        this.credentials = list.map(c => ({
          ...c,
          revealed: false,
          decryptedValue: ""
        }));
      } catch (e) {
        console.error("Failed to load credentials:", e);
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
          require_auth_on_resume: this.rulesRequireAuth
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
            if (value.startsWith('"') && value.endsWith('"')) {
              value = value.slice(1, -1).replace(/\\"/g, '"').replace(/\\n/g, '\n');
            } else if (value.startsWith("'") && value.endsWith("'")) {
              value = value.slice(1, -1);
            }
            
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
        
        let timeout = parseInt(this.appConfig.clipboard_clear_timeout);
        if (isNaN(timeout) || timeout < 0) {
           timeout = 30;
        }

        if (timeout > 0) {
          this.showToast(`Copied to clipboard (auto-clears in ${timeout}s)`, "success");
          setTimeout(async () => {
            try {
              await window.__TAURI__.core.invoke("plugin:clipboard-manager|write_text", { text: "" });
              this.showToast("Clipboard cleared", "info");
            } catch (err) {}
          }, timeout * 1000);
        } else {
          this.showToast("Copied to clipboard", "success");
        }
      } catch (e) {
        this.showToast("Failed to copy: " + e, "danger");
      }
    },

    async startEditing(cred) {
      this.editingCredId = cred.id;
      this.editingCredTags = (cred.tags || []).join(", ");
      try {
        const val = await window.__TAURI__.core.invoke("decrypt_credential", { credentialId: cred.id });
        this.editingCredValue = val;
      } catch (e) {
        this.editingCredValue = "";
      }
    },

    async viewHistory(id) {
      this.historyCredId = id;
      try {
        this.credentialHistory = await window.__TAURI__.core.invoke("get_credential_history", { credentialId: id });
        this.showHistoryModal = true;
      } catch (e) {
        this.showToast("Failed to fetch history", "danger");
      }
    },

    async rollbackTo(histItem) {
      if (!this.historyCredId) return;
      this.loading = true;
      try {
        await window.__TAURI__.core.invoke("update_credential", {
          credentialId: this.historyCredId,
          newValue: histItem.value
        });
        await this.loadCredentials(this.selectedProfile.id);
        this.showHistoryModal = false;
        this.showToast("Rolled back successfully", "success");
      } catch (e) {
        this.showToast("Failed to rollback", "danger");
      } finally {
        this.loading = false;
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
          newValue: this.editingCredValue
        });
        
        const tagArray = this.editingCredTags.split(",")
          .map(t => t.trim())
          .filter(t => t.length > 0);
          
        await window.__TAURI__.core.invoke("update_credential_tags", {
          credentialId: id,
          tags: tagArray
        });
        
        await this.loadCredentials(this.selectedProfile.id);
        this.editingCredId = null;
        this.editingCredValue = "";
        this.editingCredTags = "";
        this.showToast("Secret updated successfully", "success");
      } catch (e) {
        this.showToast("Failed to update secret", "danger");
      } finally {
        this.loading = false;
      }
    },

    triggerDeleteSecret(cred) {
      const isHighValue = ['API_KEY', 'SECRET', 'PASSWORD', 'TOKEN', 'PRIVATE_KEY'].some(kw => cred.key.toUpperCase().includes(kw));
      const warningStr = isHighValue ? `\n\n⚠️ WARNING: '${cred.key}' looks like a high-value secret. Deleting this could break dependent services.` : '';
      
      this.confirmDialog(
        "Delete Secret",
        `Are you sure you want to delete '${cred.key}'? This cannot be undone.${warningStr}`,
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

    async generateToken() {
      try {
        this.generatedToken = await window.__TAURI__.core.invoke("generate_secure_token", {
          length: parseInt(this.generatorLength, 10) || 32,
          includeSymbols: this.generatorSymbols
        });
      } catch (e) {
        this.showToast("Failed to generate token", "danger");
      }
    },

    useGeneratedToken() {
      this.newSecretValue = this.generatedToken;
      this.showGeneratorModal = false;
      this.generatedToken = "";
    },

    async bulkDelete() {
      if (this.selectedCredIds.length === 0) return;
      this.confirmDialog(
        "Delete Selected Secrets",
        `Are you sure you want to delete ${this.selectedCredIds.length} secrets? This cannot be undone.`,
        "Delete",
        async () => {
          this.loading = true;
          try {
            for (const id of this.selectedCredIds) {
              await window.__TAURI__.core.invoke("delete_credential", { credentialId: id });
            }
            this.selectedCredIds = [];
            await this.loadCredentials(this.selectedProfile.id);
            this.showToast("Secrets deleted", "success");
          } catch (e) {
            this.showToast("Failed to delete some secrets", "danger");
          } finally {
            this.loading = false;
          }
        }
      );
    },

    async bulkExport() {
      if (this.selectedCredIds.length === 0) return;
      try {
        const { save } = window.__TAURI__.dialog;
        const path = await save({
          title: "Export .env File",
          filters: [{ name: "Environment File", extensions: ["env", "txt"] }]
        });
        if (!path) return;

        this.loading = true;
        const toExport = this.credentials
          .filter(c => this.selectedCredIds.includes(c.id))
          .map(c => [c.key, c.id]);
        
        await window.__TAURI__.core.invoke("export_credentials", {
          credentialsToExport: toExport,
          exportPath: path
        });
        
        this.selectedCredIds = [];
        this.showToast("Exported successfully to " + path, "success");
      } catch (e) {
        this.showToast("Export failed: " + e, "danger");
      } finally {
        this.loading = false;
      }
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
        let shell = this.appConfig.default_shell;
        const p = this.profiles.find(x => x.id === profileId);
        
        if (p && p.session_rules && p.session_rules.allowed_shells && p.session_rules.allowed_shells.length > 0) {
          const allowed = p.session_rules.allowed_shells;
          const allowedLower = allowed.map(s => typeof s === 'string' ? s.toLowerCase() : Object.keys(s)[0].toLowerCase());
          if (!allowedLower.includes(shell.toLowerCase())) {
            shell = typeof allowed[0] === 'string' ? allowed[0] : Object.keys(allowed[0])[0];
            this.showToast(`Default shell not allowed by profile rules. Falling back to ${shell}.`, 'warning');
          }
        }
        
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
