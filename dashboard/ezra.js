class BioVAuth {
    constructor() {
        this.env = {
            WORKER_URL: 'https://auth-logs.universalezra.workers.dev/',
            RATE_LIMIT_WINDOW: 300000,
            RATE_LIMIT_MAX_ATTEMPTS: 5
        };
        this.elements = {
            scanLine: document.getElementById('scanLine'),
            status: document.getElementById('status'),
            btnContainer: document.getElementById('btnContainer'),
            loginForm: document.getElementById('loginForm'),
            fallbackBtn: document.getElementById('fallbackBtn'),
            visitBtn: document.getElementById('visitBtn'),
            webauthnBtn: document.getElementById('webauthnBtn'),
            emailInput: document.getElementById('email'),
            passwordInput: document.getElementById('password'),
            submitLogin: document.getElementById('submitLogin'),
            loadingSpinner: document.getElementById('loadingSpinner'),
            errorMsg: document.getElementById('errorMsg'),
            ipDisplay: document.getElementById('ipDisplay'),
            togglePassword: document.querySelector('.toggle-password'),
            webauthnUnsupported: document.getElementById('webauthnUnsupported'),
            ezraText: document.getElementById('ezraText'),
            container: document.querySelector('.container')
        };
        this.securityConfig = {
            maxAttempts: 3,
            blockDuration: 300000,
            cookieName: 'bioVAuthSecurity',
            loginStatusCookieName: 'isEzraLoggedIn',
            loginCookieExpiryMinutes: 10
        };
        this.state = {
            webauthnSupported: false,
            clientInfo: {}
        };
        this.init();
    }
    async init() {
        this.startBiometricAnimation();
        await this.collectClientInfo();
        this.setupEventListeners();
        this.checkWebAuthnSupport();
        this.securitySystem = new SecuritySystem(this.securityConfig.maxAttempts, this.securityConfig.blockDuration, this.securityConfig.cookieName);
    }
    async collectClientInfo() {
        try {
            const controller = new AbortController();
            const id = setTimeout(() => controller.abort(), 3000);
            const ipResponse = await fetch('https://api.ipify.org?format=json', {
                signal: controller.signal
            });
            clearTimeout(id);
            if (!ipResponse.ok) throw new Error(`HTTP error! status: ${ipResponse.status}`);
            const ipData = await ipResponse.json();
            this.state.clientInfo = {
                ip: ipData.ip,
                userAgent: navigator.userAgent,
                platform: navigator.platform,
                timestamp: new Date().toISOString(),
                screenResolution: `${window.screen.width}x${window.screen.height}`,
                language: navigator.language
            };
            this.elements.ipDisplay.textContent = `IP: ${ipData.ip} • ${navigator.platform}`;
        } catch (error) {
            console.error('Error collecting client info:', error);
            this.state.clientInfo = {
                ip: 'unavailable',
                userAgent: navigator.userAgent,
                platform: navigator.platform || 'unknown',
                timestamp: new Date().toISOString(),
                screenResolution: `${window.screen.width}x${window.screen.height}`,
                language: navigator.language || 'unknown'
            };
            this.elements.ipDisplay.textContent = 'Network: Secure • Private';
        }
    }
    startBiometricAnimation() {
        this.elements.scanLine.style.opacity = '1';
        this.updateStatus('Initializing security', 'info');
        setTimeout(() => {
            this.elements.scanLine.style.opacity = '0';
            this.updateStatus('System ready', 'success');
            this.elements.btnContainer.style.display = 'flex';
        }, 2000);
    }
    updateStatus(message, type = 'info') {
        this.elements.status.textContent = message;
        this.elements.status.className = 'status';
        if (type) this.elements.status.classList.add(type);
    }
    setupEventListeners() {
        this.elements.fallbackBtn.addEventListener('click', () => this.showLoginForm());
        this.elements.visitBtn.addEventListener('click', () => window.location.href = 'https://universalezra.netlify.app');
        this.elements.webauthnBtn.addEventListener('click', () => {
            if (this.state.webauthnSupported) this.initiateWebAuthn();
            else this.elements.webauthnUnsupported.style.display = 'block';
        });
        this.elements.loginForm.addEventListener('submit', async e => {
            e.preventDefault();
            await this.handleLogin();
        });
        this.elements.togglePassword.addEventListener('click', () => this.togglePasswordVisibility());
        this.elements.ezraText.addEventListener('click', () => this.handleEzraClick());
    }
    checkWebAuthnSupport() {
        if (!window.PublicKeyCredential) {
            this.state.webauthnSupported = false;
            this.elements.webauthnBtn.disabled = true;
            this.elements.webauthnUnsupported.style.display = 'block';
            return;
        }
        PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(available => {
            this.state.webauthnSupported = available;
            if (!available) this.elements.webauthnUnsupported.style.display = 'block';
        }).catch(() => {
            this.state.webauthnSupported = false;
            this.elements.webauthnUnsupported.style.display = 'block';
        });
    }
    showLoginForm() {
        this.elements.btnContainer.style.display = 'none';
        this.elements.loginForm.style.display = 'block';
        this.elements.emailInput.focus();
        this.updateStatus(' Enter your credentials', 'info');
    }
    async handleLogin() {
        if (this.securitySystem.isBlocked()) {
            this.showBlockedMessage();
            return;
        }
        const username = this.elements.emailInput.value.trim().toLowerCase();
        const password = this.elements.passwordInput.value;
        if (!username || !password) {
            this.showError('Please fill in all fields (username and password).');
            return;
        }
        this.setLoadingState(true);
        try {
            const response = await fetch(this.env.WORKER_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Client-IP': this.state.clientInfo.ip,
                    'X-Client-UA': this.state.clientInfo.userAgent
                },
                body: JSON.stringify({
                    username,
                    password
                })
            });
            const responseData = await response.json();
            if (responseData.authenticated) {
                this.setCookie(this.securityConfig.loginStatusCookieName, 'true', this.securityConfig.loginCookieExpiryMinutes);
                this.securitySystem.resetAttempts();
                this.updateStatus('Authentication successful', 'success');
                window.location.href = 'secret.html';
            } else {
                this.handleFailedLogin(responseData.message || 'Invalid username or password');
            }
        } catch (error) {
            console.error('Login error: Try again', error);
            this.showError('Login failed');
            this.securitySystem.recordFailedAttempt();
        } finally {
            this.setLoadingState(false);
        }
    }
    handleSuccessfulLogin() {
        this.setCookie(this.securityConfig.loginStatusCookieName, 'true', this.securityConfig.loginCookieExpiryMinutes);
        this.securitySystem.resetAttempts();
        this.updateStatus('Authentication successful', 'success');
        this.elements.errorMsg.textContent = '';
        window.location.href = 'secret.html';
    }
    handleFailedLogin(errorMessage) {
        this.securitySystem.recordFailedAttempt();
        const attemptsLeft = this.securitySystem.maxAttempts - this.securitySystem.attemptData.attempts;
        let displayMessage = errorMessage + (attemptsLeft > 0 ? ` (${attemptsLeft} ${attemptsLeft===1?'attempt':'attempts'} left)` : '');
        this.showError(displayMessage);
        if (this.securitySystem.isBlocked()) this.showBlockedMessage();
        this.elements.passwordInput.value = '';
        this.elements.passwordInput.focus();
        this.elements.loginForm.classList.add('shake');
        setTimeout(() => this.elements.loginForm.classList.remove('shake'), 500);
    }
    showBlockedMessage() {
        let remainingTime = this.securitySystem.getRemainingBlockTime();
        const updateCountdown = () => {
            const minutes = Math.floor(remainingTime / 60);
            const seconds = remainingTime % 60;
            this.showError(`Too many attempts. Wait ${minutes}m ${seconds}s.`);
        };
        this.setLoadingState(false);
        this.elements.submitLogin.disabled = true;
        updateCountdown();
        const countdownInterval = setInterval(() => {
            remainingTime = this.securitySystem.getRemainingBlockTime();
            if (remainingTime <= 0) {
                clearInterval(countdownInterval);
                this.elements.errorMsg.textContent = '';
                this.elements.submitLogin.disabled = false;
                return;
            }
            updateCountdown();
        }, 1000);
    }
    showError(message) {
        this.elements.errorMsg.textContent = message;
        this.elements.errorMsg.style.display = 'block';
        setTimeout(() => {
            if (this.elements.errorMsg.textContent === message) this.elements.errorMsg.style.display = 'none';
        }, 5000);
    }
    setLoadingState(isLoading) {
        this.elements.submitLogin.disabled = isLoading;
        this.elements.loadingSpinner.style.display = isLoading ? 'inline-block' : 'none';
        this.elements.submitLogin.querySelector('.btn-text').textContent = isLoading ? 'Authenticating' : 'Login';
    }
    togglePasswordVisibility() {
        const isPassword = this.elements.passwordInput.type === 'password';
        this.elements.passwordInput.type = isPassword ? 'text' : 'password';
        this.elements.togglePassword.textContent = isPassword ? '😌' : '🙂';
        this.elements.togglePassword.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
    }
    
    // --- FUNGSI BARU ADA DI SINI ---
    async initiateWebAuthn() {
        if (!this.state.webauthnSupported) {
          this.updateStatus('WebAuthn not supported', 'error');
          return;
        }

        this.updateStatus('Mempersiapkan sensor biometrik...', 'info');

        try {
          // Opsi untuk membuat kredensial baru.
          // Di aplikasi nyata, 'challenge' dan 'user.id' akan datang dari server.
          // Di sini kita buat data dummy hanya untuk demo.
          const publicKeyCredentialCreationOptions = {
            // Challenge: Data acak dari server untuk mencegah replay attacks.
            challenge: new Uint8Array(32), // Kita buat challenge dummy

            // RP (Relying Party): Informasi tentang website Anda.
            rp: {
              name: "Universal Ezra Auth",
              id: window.location.hostname, // Otomatis menggunakan domain saat ini
            },

            // User: Informasi tentang pengguna yang mendaftar.
            user: {
              id: this.str2ab("user-dummy-id-" + Date.now()), // ID unik untuk pengguna (dummy)
              name: "user@example.com",
              displayName: "Demo User",
            },

            // Algoritma kriptografi yang diterima.
            pubKeyCredParams: [{ alg: -7, type: "public-key" }], // ES256, standar yang umum

            // Timeout untuk operasi ini.
            timeout: 60000,

            // Meminta authenticator yang ada di perangkat (spt sidik jari di HP).
            authenticatorSelection: {
              authenticatorAttachment: "platform", // 'platform' untuk sensor bawaan
              requireResidentKey: true,
              userVerification: "required", // 'required' untuk WAJIB meminta biometrik/PIN
            },
            
            attestation: "none" // Tidak perlu verifikasi attestasi untuk demo ini
          };

          // Inisialisasi proses pendaftaran dan tunggu sensor sidik jari
          this.updateStatus('Mohon pindai sidik jari Anda...', 'info');
          const credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions
          });

          // Jika berhasil, tampilkan hasilnya
          console.log('Kredensial berhasil dibuat:', credential);
          const credentialId = this.ab2b64url(credential.rawId);
          
          this.updateStatus('Sidik Jari Terdeteksi!', 'success');
          // Tampilkan ID kredensial yang unik untuk sidik jari ini
          setTimeout(() => {
              this.updateStatus(`Credential ID: ...${credentialId.substring(credentialId.length - 15)}`, 'info');
          }, 1500);


        } catch (err) {
          // Tangani jika pengguna membatalkan atau terjadi error
          console.error("WebAuthn Error:", err);
          if (err.name === "NotAllowedError") {
            this.updateStatus('Proses dibatalkan oleh pengguna', 'error');
          } else {
            this.updateStatus('Gagal mendeteksi sidik jari', 'error');
          }
        }
    }

    toggleFullscreen() {
        const doc = document.documentElement;
        if (!document.fullscreenElement) {
            if (doc.requestFullscreen) {
                doc.requestFullscreen();
            } else if (doc.mozRequestFullScreen) {
                doc.mozRequestFullScreen();
            } else if (doc.webkitRequestFullscreen) {
                doc.webkitRequestFullscreen();
            } else if (doc.msRequestFullscreen) {
                doc.msRequestFullscreen();
            }
            this.updateStatus('Entering fullscreen mode', 'info');
        } else {
            if (document.exitFullscreen) {
                document.exitFullscreen();
            } else if (document.mozCancelFullScreen) {
                document.mozCancelFullScreen();
            } else if (document.webkitExitFullscreen) {
                document.webkitExitFullscreen();
            } else if (document.msExitFullscreen) {
                document.msExitFullscreen();
            }
            this.updateStatus('Exiting fullscreen mode', 'info');
        }
    }
    handleEzraClick() {
        this.toggleFullscreen();
        this.elements.container.style.boxShadow = '0 0 20px 5px var(--primary)';
        this.updateStatus('Sistem Ezra', 'success');
        const originalShadow = getComputedStyle(this.elements.container).boxShadow;
        setTimeout(() => {
            this.elements.container.style.boxShadow = originalShadow;
            this.updateStatus('System ready', 'success');
        }, 3000);
    }
    setCookie(name, value, minutes) {
        const d = new Date();
        d.setTime(d.getTime() + (minutes * 60 * 1000));
        const expires = "expires=" + d.toUTCString();
        document.cookie = name + "=" + value + ";" + expires + ";path=/;SameSite=Strict;Secure";
    }
    getCookie(name) {
        const nameEQ = name + "=";
        const ca = document.cookie.split(';');
        for (let i = 0; i < ca.length; i++) {
            let c = ca[i];
            while (c.charAt(0) === ' ') c = c.substring(1, c.length);
            if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
        }
        return null;
    }

    // --- FUNGSI HELPER BARU ADA DI SINI ---
    str2ab(str) {
        const buf = new ArrayBuffer(str.length);
        const bufView = new Uint8Array(buf);
        for (let i = 0, strLen = str.length; i < strLen; i++) {
          bufView[i] = str.charCodeAt(i);
        }
        return buf;
    }
    ab2b64url(buffer) {
        return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
    }
}
class SecuritySystem {
    constructor(maxAttempts, blockDuration, cookieName) {
        this.maxAttempts = maxAttempts;
        this.blockDuration = blockDuration;
        this.cookieName = cookieName;
        this.attemptData = this.loadAttemptData();
    }
    loadAttemptData() {
        try {
            const cookieData = this.getCookie(this.cookieName);
            const data = cookieData ? JSON.parse(decodeURIComponent(cookieData)) : this.getDefaultData();
            return this.validateData(data) ? data : this.getDefaultData();
        } catch (e) {
            console.error('Failed to parse', e);
            return this.getDefaultData();
        }
    }
    getDefaultData() {
        return {
            attempts: 0,
            lastAttempt: null,
            blockUntil: null
        };
    }
    validateData(data) {
        return data && typeof data === 'object' && 'attempts' in data && 'lastAttempt' in data && 'blockUntil' in data;
    }
    saveAttemptData() {
        const expires = new Date();
        expires.setDate(expires.getDate() + 1);
        const data = encodeURIComponent(JSON.stringify(this.attemptData));
        document.cookie = `${this.cookieName}=${data}; expires=${expires.toUTCString()}; path=/; SameSite=Strict; Secure`;
    }
    getCookie(name) {
        return document.cookie.split(';').map(c => c.trim()).find(c => c.startsWith(name + '='))?.substring(name.length + 1);
    }
    recordFailedAttempt() {
        const now = new Date();
        this.attemptData.attempts++;
        this.attemptData.lastAttempt = now.toISOString();
        if (this.attemptData.attempts >= this.maxAttempts) {
            this.attemptData.blockUntil = new Date(now.getTime() + this.blockDuration).toISOString();
        }
        this.saveAttemptData();
    }
    resetAttempts() {
        this.attemptData = this.getDefaultData();
        this.saveAttemptData();
    }
    isBlocked() {
        if (!this.attemptData.blockUntil) return false;
        const blockUntil = new Date(this.attemptData.blockUntil);
        const now = new Date();
        if (now > blockUntil) {
            this.resetAttempts();
            return false;
        }
        return true;
    }
    getRemainingBlockTime() {
        if (!this.isBlocked()) return 0;
        return Math.round((new Date(this.attemptData.blockUntil) - new Date()) / 1000);
    }
}
document.addEventListener('DOMContentLoaded', () => {
    new BioVAuth();
});
