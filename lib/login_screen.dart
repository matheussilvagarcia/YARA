import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:anotherrunner/l10n/app_localizations.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'auth_service.dart';
import 'main.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final AuthService _auth = AuthService();
  final TextEditingController _emailController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();
  final TextEditingController _confirmPasswordController = TextEditingController();
  final TextEditingController _otpController = TextEditingController();

  bool _isLoading = false;
  bool _isRegistering = false;

  void _toggleLoading() {
    if (mounted) {
      setState(() {
        _isLoading = !_isLoading;
      });
    }
  }

  void _toggleMode() {
    setState(() {
      _isRegistering = !_isRegistering;
      _confirmPasswordController.clear();
    });
  }

  String _authErrorMessage(AppLocalizations l10n, String? code) {
    switch (code) {
      case 'invalid-code':
        return l10n.invalidOtp;
      case 'expired-code':
        return l10n.otpExpired;
      case 'too-many-attempts':
        return l10n.otpTooManyAttempts;
      case 'too-many-requests':
        return l10n.tooManyRequests;
      case 'email-already-in-use':
        return l10n.emailInUsePassword;
      case 'weak-password':
        return l10n.passwordTooShort;
      case 'account-exists-with-different-credential':
        return l10n.accountExistsDifferentMethod;
      case 'invalid-credential':
      case 'invalid-email':
      case 'wrong-password':
      case 'user-not-found':
      case 'user-disabled':
        return l10n.signInError;
      default:
        return l10n.actionFailed;
    }
  }

  void _showAuthError(AuthResult result) {
    if (!mounted || result.success || result.cancelled) return;
    final l10n = AppLocalizations.of(context)!;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(_authErrorMessage(l10n, result.errorCode))),
    );
  }

  Future<void> _signInWithEmail() async {
    final l10n = AppLocalizations.of(context)!;

    if (_emailController.text.isEmpty || _passwordController.text.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(l10n.fillAllFields)));
      return;
    }
    _toggleLoading();
    final result = await _auth.signInWithEmail(
      _emailController.text.trim(),
      _passwordController.text.trim(),
    );
    _toggleLoading();
    _showAuthError(result);
  }

  Future<void> _resetPassword() async {
    final l10n = AppLocalizations.of(context)!;
    final email = _emailController.text.trim();

    if (email.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(l10n.fillEmailToReset)));
      return;
    }

    _toggleLoading();
    final success = await _auth.resetPassword(email);
    _toggleLoading();

    if (!mounted) return;

    if (success) {
      showDialog(
        context: context,
        builder: (dialogContext) => AlertDialog(
          title: Text(l10n.resetPasswordTitle),
          content: RichText(
            text: TextSpan(
              style: Theme.of(context).textTheme.bodyMedium,
              children: [
                TextSpan(text: '${l10n.passwordResetSent}\n\n'),
                TextSpan(
                  text: l10n.checkSpamMessage,
                  style: const TextStyle(fontWeight: FontWeight.bold),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext),
              child: Text(l10n.okBtn),
            ),
          ],
        ),
      );
    } else {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(l10n.errorSendingOtp)));
    }
  }

  Future<void> _startRegistration() async {
    final l10n = AppLocalizations.of(context)!;
    final email = _emailController.text.trim();
    final password = _passwordController.text.trim();
    final confirmPassword = _confirmPasswordController.text.trim();

    if (email.isEmpty || password.isEmpty || confirmPassword.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(l10n.fillAllFields)));
      return;
    }

    if (password != confirmPassword) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(l10n.passwordsNotMatch)));
      return;
    }

    if (password.length < 6) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(l10n.passwordTooShort)));
      return;
    }

    _toggleLoading();
    final result = await _auth.requestEmailCode(email);
    _toggleLoading();

    if (!mounted) return;

    if (result.success) {
      _showOtpDialog(email, password);
    } else if (result.errorCode == 'too-many-requests') {
      _showAuthError(result);
    } else {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(l10n.errorSendingOtp)));
    }
  }

  void _showOtpDialog(String email, String password) {
    final l10n = AppLocalizations.of(context)!;
    _otpController.clear();
    bool verifying = false;

    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (dialogContext) => StatefulBuilder(
        builder: (dialogContext, setDialogState) => AlertDialog(
        title: Text(l10n.confirmEmailTitle),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            RichText(
              text: TextSpan(
                style: Theme.of(context).textTheme.bodyMedium,
                children: [
                  TextSpan(text: '${l10n.otpSentMessage(email)}\n\n'),
                  TextSpan(
                    text: l10n.checkSpamMessage,
                    style: const TextStyle(fontWeight: FontWeight.bold),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _otpController,
              keyboardType: TextInputType.number,
              maxLength: 6,
              decoration: InputDecoration(
                labelText: l10n.otpCodeLabel,
                border: const OutlineInputBorder(),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: verifying ? null : () => Navigator.pop(dialogContext),
            child: Text(l10n.cancelBtn),
          ),
          ElevatedButton(
            onPressed: verifying
                ? null
                : () async {
                    final code = _otpController.text.trim();
                    if (code.length != 6) {
                      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(l10n.invalidOtp)));
                      return;
                    }

                    setDialogState(() => verifying = true);
                    final result = await _auth.registerWithEmailCode(email, password, code);
                    if (!dialogContext.mounted) return;

                    if (result.success) {
                      Navigator.pop(dialogContext);
                      return;
                    }

                    setDialogState(() => verifying = false);
                    if (result.errorCode != 'invalid-code') {
                      Navigator.pop(dialogContext);
                    }
                    _showAuthError(result);
                  },
            child: verifying
                ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
                : Text(l10n.confirmBtn),
          ),
        ],
      ),
      ),
    );
  }

  Future<void> _signInWithGoogle() async {
    _toggleLoading();
    final result = await _auth.signInWithGoogle();
    _toggleLoading();
    _showAuthError(result);
  }

  Future<void> _signInWithApple() async {
    _toggleLoading();
    final result = await _auth.signInWithApple();
    _toggleLoading();
    _showAuthError(result);
  }

  Future<void> _changeLanguage(String languageCode) async {
    localeNotifier.value = Locale(languageCode);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('languageCode', languageCode);
  }

  Widget _buildFlag(String flag, String langCode) {
    return GestureDetector(
      onTap: () => _changeLanguage(langCode),
      child: Text(
        flag,
        style: const TextStyle(fontSize: 28),
      ),
    );
  }

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    _otpController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final isDarkMode = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                l10n.welcomeTo,
                textAlign: TextAlign.center,
                style: const TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.w500,
                ),
              ),
              const SizedBox(height: 16),
              Image.asset(
                isDarkMode
                    ? 'lib/assets/Graphic resource (White).png'
                    : 'lib/assets/Graphic resource.png',
                height: 48,
              ),
              const SizedBox(height: 16),
              Text(
                l10n.chooseLoginMethod,
                textAlign: TextAlign.center,
                style: const TextStyle(
                  fontSize: 14,
                  color: Colors.grey,
                ),
              ),
              const SizedBox(height: 48),
              TextField(
                controller: _emailController,
                keyboardType: TextInputType.emailAddress,
                decoration: InputDecoration(
                  labelText: l10n.emailLabel,
                  border: const OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: _passwordController,
                obscureText: true,
                decoration: InputDecoration(
                  labelText: l10n.passwordLabel,
                  border: const OutlineInputBorder(),
                ),
              ),
              if (_isRegistering) ...[
                const SizedBox(height: 16),
                TextField(
                  controller: _confirmPasswordController,
                  obscureText: true,
                  decoration: InputDecoration(
                    labelText: l10n.confirmPasswordLabel,
                    border: const OutlineInputBorder(),
                  ),
                ),
              ],
              const SizedBox(height: 24),
              if (_isLoading)
                const Center(child: CircularProgressIndicator())
              else ...[
                ElevatedButton(
                  onPressed: _isRegistering ? _startRegistration : _signInWithEmail,
                  child: Text(_isRegistering ? l10n.createAccountBtn : l10n.signInBtn),
                ),
                const SizedBox(height: 8),
                TextButton(
                  onPressed: _toggleMode,
                  child: Text(_isRegistering
                      ? l10n.alreadyHaveAccount
                      : l10n.dontHaveAccount),
                ),
                const Divider(height: 48),
                OutlinedButton.icon(
                  onPressed: _signInWithGoogle,
                  icon: SvgPicture.asset(
                    'lib/assets/Google.svg',
                    width: 24,
                    height: 24,
                  ),
                  label: Text(l10n.signInWithGoogleBtn),
                ),
                if (Platform.isIOS) ...[
                  const SizedBox(height: 16),
                  OutlinedButton.icon(
                    onPressed: _signInWithApple,
                    icon: const Icon(Icons.apple, color: Colors.black, size: 24),
                    label: Text(l10n.signInWithAppleBtn),
                  ),
                ],
                const SizedBox(height: 8),
                TextButton(
                  onPressed: _resetPassword,
                  child: Text(
                    l10n.forgotPasswordBtn,
                    style: const TextStyle(color: Colors.grey),
                  ),
                ),
                const SizedBox(height: 32),
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    _buildFlag('\u{1F1FA}\u{1F1F8}', 'en'),
                    const SizedBox(width: 16),
                    _buildFlag('\u{1F1E7}\u{1F1F7}', 'pt'),
                    const SizedBox(width: 16),
                    _buildFlag('\u{1F1EB}\u{1F1F7}', 'fr'),
                    const SizedBox(width: 16),
                    _buildFlag('\u{1F1E9}\u{1F1EA}', 'de'),
                    const SizedBox(width: 16),
                    _buildFlag('\u{1F1F8}\u{1F1EA}', 'sv'),
                  ],
                ),
              ]
            ],
          ),
        ),
      ),
    );
  }
}