import 'dart:io';
import 'dart:math';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:cloud_functions/cloud_functions.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:flutter/foundation.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';
import 'firebase_options.dart';

/// Result of an authentication action, with an optional error code the UI
/// translates into a message.
class AuthResult {
  final bool success;
  final bool cancelled;
  final String? errorCode;

  const AuthResult._(this.success, this.cancelled, this.errorCode);

  const AuthResult.ok() : this._(true, false, null);
  const AuthResult.cancelled() : this._(false, true, null);
  const AuthResult.error(String code) : this._(false, false, code);
}

enum LinkOutcome { linked, merged, alreadyLinked, cancelled, providerInUse, error }

class AuthService {
  static const String googleProviderId = 'google.com';
  static const String appleProviderId = 'apple.com';
  static const String passwordProviderId = 'password';
  static const String _linkAppName = 'yara-account-link';

  final FirebaseAuth _auth = FirebaseAuth.instance;
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  final FirebaseFunctions _functions = FirebaseFunctions.instance;

  final GoogleSignIn _googleSignIn = GoogleSignIn(
    serverClientId: '1049630213063-eum06jfp8t62ej7fb7gdh23l252qcj8p.apps.googleusercontent.com',
  );

  Stream<User?> get authStateChanges => _auth.authStateChanges();

  List<String> get linkedProviders =>
      _auth.currentUser?.providerData.map((p) => p.providerId).toList() ?? const [];

  Future<void> _saveUserToFirestore(User user) async {
    try {
      final userRef = _firestore.collection('users').doc(user.uid);
      final docSnapshot = await userRef.get();

      if (!docSnapshot.exists) {
        await userRef.set({
          'createdAt': FieldValue.serverTimestamp(),
          'isPremium': false,
        }, SetOptions(merge: true));
      }
    } catch (e) {
      debugPrint('Erro ao salvar dados no Firestore: $e');
    }
  }

  Future<bool> resetPassword(String email) async {
    try {
      await _auth.sendPasswordResetEmail(email: email);
      return true;
    } catch (e) {
      debugPrint('Password reset error: $e');
      return false;
    }
  }

  String _functionErrorCode(FirebaseFunctionsException e) {
    if (e.code == 'resource-exhausted') return 'too-many-requests';
    if (e.code == 'already-exists') return 'email-already-in-use';
    final message = e.message ?? '';
    const known = [
      'invalid-code',
      'expired-code',
      'too-many-attempts',
      'weak-password',
      'provider-already-linked',
    ];
    return known.contains(message) ? message : e.code;
  }

  /// Asks the server to generate and email a verification code.
  Future<AuthResult> requestEmailCode(String email) async {
    try {
      await _functions.httpsCallable('requestEmailCode').call(<String, dynamic>{
        'email': email,
        'tzOffsetMinutes': DateTime.now().timeZoneOffset.inMinutes,
      });
      return const AuthResult.ok();
    } on FirebaseFunctionsException catch (e) {
      debugPrint('requestEmailCode error: ${e.code}');
      return AuthResult.error(_functionErrorCode(e));
    } catch (e) {
      debugPrint('requestEmailCode error: $e');
      return const AuthResult.error('unknown');
    }
  }

  /// Verifies the code on the server, which creates the account, then signs in.
  Future<AuthResult> registerWithEmailCode(String email, String password, String code) async {
    try {
      await _functions.httpsCallable('createAccountWithCode').call(<String, dynamic>{
        'email': email,
        'password': password,
        'code': code,
      });
      final credential = await _auth.signInWithEmailAndPassword(email: email, password: password);
      if (credential.user != null) {
        await _saveUserToFirestore(credential.user!);
      }
      return const AuthResult.ok();
    } on FirebaseFunctionsException catch (e) {
      debugPrint('createAccountWithCode error: ${e.code} ${e.message}');
      return AuthResult.error(_functionErrorCode(e));
    } on FirebaseAuthException catch (e) {
      return AuthResult.error(e.code);
    } catch (e) {
      debugPrint('registerWithEmailCode error: $e');
      return const AuthResult.error('unknown');
    }
  }

  Future<AuthResult> signInWithEmail(String email, String password) async {
    try {
      await _auth.signInWithEmailAndPassword(email: email, password: password);
      return const AuthResult.ok();
    } on FirebaseAuthException catch (e) {
      debugPrint('Email sign in error: ${e.code}');
      return AuthResult.error(e.code);
    } catch (e) {
      debugPrint('Email sign in error: $e');
      return const AuthResult.error('unknown');
    }
  }

  String _generateNonce([int length = 32]) {
    const charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._';
    final random = Random.secure();
    return List.generate(length, (_) => charset[random.nextInt(charset.length)]).join();
  }

  Future<AuthCredential?> _appleCredential() async {
    final rawNonce = _generateNonce();
    final nonce = sha256.convert(utf8.encode(rawNonce)).toString();

    final appleCredential = await SignInWithApple.getAppleIDCredential(
      scopes: [
        AppleIDAuthorizationScopes.email,
        AppleIDAuthorizationScopes.fullName,
      ],
      nonce: nonce,
    );

    if (appleCredential.identityToken == null) return null;

    return OAuthProvider(appleProviderId).credential(
      idToken: appleCredential.identityToken,
      rawNonce: rawNonce,
      accessToken: appleCredential.authorizationCode,
    );
  }

  Future<AuthCredential?> _googleCredential({bool chooseAccount = false}) async {
    if (chooseAccount) {
      await _googleSignIn.signOut();
    }
    final GoogleSignInAccount? googleUser = await _googleSignIn.signIn();
    if (googleUser == null) return null;

    final GoogleSignInAuthentication googleAuth = await googleUser.authentication;
    return GoogleAuthProvider.credential(
      accessToken: googleAuth.accessToken,
      idToken: googleAuth.idToken,
    );
  }

  Future<AuthCredential?> _credentialFor(String providerId, {bool chooseAccount = false}) {
    if (providerId == appleProviderId) return _appleCredential();
    return _googleCredential(chooseAccount: chooseAccount);
  }

  bool _isCancellation(Object e) =>
      e is SignInWithAppleAuthorizationException && e.code == AuthorizationErrorCode.canceled;

  Future<AuthResult> _signInWithProvider(String providerId) async {
    try {
      final credential = await _credentialFor(providerId);
      if (credential == null) return const AuthResult.cancelled();

      final userCredential = await _auth.signInWithCredential(credential);
      if (userCredential.user != null) {
        await _saveUserToFirestore(userCredential.user!);
      }
      return const AuthResult.ok();
    } on FirebaseAuthException catch (e) {
      debugPrint('$providerId sign in error: ${e.code}');
      return AuthResult.error(e.code);
    } catch (e) {
      if (_isCancellation(e)) return const AuthResult.cancelled();
      debugPrint('$providerId sign in error: $e');
      return const AuthResult.error('unknown');
    }
  }

  Future<AuthResult> signInWithApple() => _signInWithProvider(appleProviderId);

  Future<AuthResult> signInWithGoogle() => _signInWithProvider(googleProviderId);

  Future<FirebaseApp> _linkApp() async {
    for (final app in Firebase.apps) {
      if (app.name == _linkAppName) return app;
    }
    return Firebase.initializeApp(
      name: _linkAppName,
      options: DefaultFirebaseOptions.currentPlatform,
    );
  }

  /// Links a Google or Apple sign-in to the current account.
  ///
  /// When that Google/Apple identity already has its own YARA account (for
  /// example Apple with "Hide My Email"), the server merges its data into the
  /// current account, moves the sign-in method over and deletes the old one.
  Future<LinkOutcome> linkProvider(String providerId) async {
    final currentUser = _auth.currentUser;
    if (currentUser == null) return LinkOutcome.error;
    if (linkedProviders.contains(providerId)) return LinkOutcome.alreadyLinked;

    FirebaseAuth? linkAuth;
    try {
      final credential = await _credentialFor(providerId, chooseAccount: true);
      if (credential == null) return LinkOutcome.cancelled;

      // Sign in on a separate Firebase app so the current session is kept.
      linkAuth = FirebaseAuth.instanceFor(app: await _linkApp());
      UserCredential other;
      try {
        other = await linkAuth.signInWithCredential(credential);
      } on FirebaseAuthException catch (e) {
        if (e.code == 'account-exists-with-different-credential') {
          await currentUser.linkWithCredential(credential);
          await currentUser.reload();
          return LinkOutcome.linked;
        }
        rethrow;
      }

      final otherUser = other.user;
      if (otherUser == null) return LinkOutcome.error;
      if (otherUser.uid == currentUser.uid) return LinkOutcome.alreadyLinked;

      final otherIdToken = await otherUser.getIdToken(true);
      final response = await _functions.httpsCallable('mergeAccounts').call(<String, dynamic>{
        'otherIdToken': otherIdToken,
      });

      await currentUser.reload();
      await currentUser.getIdToken(true);

      final data = Map<String, dynamic>.from(response.data as Map);
      if (data['alreadyLinked'] == true) return LinkOutcome.alreadyLinked;
      return LinkOutcome.merged;
    } on FirebaseFunctionsException catch (e) {
      debugPrint('mergeAccounts error: ${e.code} ${e.message}');
      if (e.message == 'provider-already-linked') return LinkOutcome.providerInUse;
      return LinkOutcome.error;
    } on FirebaseAuthException catch (e) {
      debugPrint('linkProvider error: ${e.code}');
      if (e.code == 'provider-already-linked' || e.code == 'credential-already-in-use') {
        return LinkOutcome.providerInUse;
      }
      return LinkOutcome.error;
    } catch (e) {
      if (_isCancellation(e)) return LinkOutcome.cancelled;
      debugPrint('linkProvider error: $e');
      return LinkOutcome.error;
    } finally {
      if (linkAuth != null) {
        try {
          await linkAuth.signOut();
        } catch (_) {}
      }
    }
  }

  /// Whether the account can confirm its identity with a password.
  bool get usesPasswordOnly {
    final providers = linkedProviders;
    return providers.contains(passwordProviderId) &&
        !providers.contains(googleProviderId) &&
        !(Platform.isIOS && providers.contains(appleProviderId));
  }

  /// Confirms the user's identity right before a sensitive action.
  Future<AuthResult> reauthenticate({String? password}) async {
    final user = _auth.currentUser;
    if (user == null) return const AuthResult.error('no-user');

    try {
      AuthCredential? credential;
      final providers = linkedProviders;
      if (password != null && user.email != null) {
        credential = EmailAuthProvider.credential(email: user.email!, password: password);
      } else if (Platform.isIOS && providers.contains(appleProviderId)) {
        credential = await _appleCredential();
      } else if (providers.contains(googleProviderId)) {
        credential = await _googleCredential();
      }
      if (credential == null) return const AuthResult.cancelled();

      await user.reauthenticateWithCredential(credential);
      return const AuthResult.ok();
    } on FirebaseAuthException catch (e) {
      debugPrint('Reauthentication error: ${e.code}');
      return AuthResult.error(e.code);
    } catch (e) {
      if (_isCancellation(e)) return const AuthResult.cancelled();
      debugPrint('Reauthentication error: $e');
      return const AuthResult.error('unknown');
    }
  }

  Future<void> signOut() async {
    try {
      await _googleSignIn.signOut();
      await _auth.signOut();
    } catch (e) {
      debugPrint('Sign out error: $e');
    }
  }

  /// Deletes the account on the server: profile, runs, stats, username,
  /// community membership and the Auth user. Call [reauthenticate] first.
  ///
  /// Returns `requires-recent-login` when the caller must reauthenticate first.
  Future<AuthResult> deleteAccount() async {
    final user = _auth.currentUser;
    if (user == null) return const AuthResult.error('no-user');

    try {
      // Send a token that carries the fresh sign-in time.
      await user.getIdToken(true);
      await _functions.httpsCallable('deleteAccount').call();
      await signOut();
      return const AuthResult.ok();
    } on FirebaseFunctionsException catch (e) {
      debugPrint('deleteAccount error: ${e.code} ${e.message}');
      return AuthResult.error(e.message == 'requires-recent-login' ? 'requires-recent-login' : e.code);
    } on FirebaseAuthException catch (e) {
      debugPrint('Erro FirebaseAuth ao deletar: ${e.code}');
      return AuthResult.error(e.code);
    } catch (e) {
      debugPrint('Erro geral ao deletar: $e');
      return const AuthResult.error('unknown');
    }
  }
}
