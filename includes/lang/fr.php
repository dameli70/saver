<?php
// French (default)
return [
    // Common
    'common.theme' => 'Thème',
    'common.language' => 'Langue',
    'common.lang_fr' => 'FR',
    'common.lang_en' => 'EN',
    'common.home' => 'Accueil',
    'common.faq' => 'FAQ',
    'common.login' => 'Connexion',
    'common.logout' => 'Déconnexion',
    'common.create_account' => 'Créer un compte',
    'common.email' => 'E-mail',
    'common.password' => 'Mot de passe',
    'common.back' => 'Retour',
    'common.cancel' => 'Annuler',
    'common.confirm' => 'Confirmer',
    'common.close' => 'Fermer',
    'common.network_error' => 'Erreur réseau',

    // Theme toggle (assets/theme.js)
    'theme.switch_to_light' => 'Passer au mode clair',
    'theme.switch_to_dark' => 'Passer au mode sombre',

    // Navigation
    'nav.dashboard' => 'Tableau de bord',
    'nav.create_code' => 'Créer un code',
    'nav.my_codes' => 'Mes codes',
    'nav.rooms' => 'Salles',
    'nav.notifications' => 'Notifications',
    'nav.backups' => 'Sauvegardes',
    'nav.vault' => 'Coffre',
    'nav.setup' => 'Configuration',
    'nav.account' => 'Compte',
    'nav.admin' => 'Admin',
    'nav.verify_email' => 'Vérifier l’e-mail',

    // Page titles / headings
    'page.dashboard' => 'Tableau de bord',
    'page.create_code' => 'Créer un code',
    'page.my_codes' => 'Mes codes',
    'page.vault_settings' => 'Paramètres du coffre',
    'page.rooms' => 'Salles d’épargne',
    'page.room' => 'Salle',
    'page.notifications' => 'Notifications',
    'page.backups' => 'Sauvegardes',
    'page.account' => 'Compte',
    'page.admin' => 'Admin',
    'page.setup' => 'Configuration',
    'page.install' => 'Installation',
    'page.signup' => 'Créer un compte',
    'page.forgot' => 'Mot de passe oublié',
    'page.reset' => 'Réinitialiser le mot de passe',

    'heading.account' => 'Votre compte',
    'heading.admin' => 'Tableau de bord admin',

    'admin.intro' => 'Gérez les utilisateurs et tous les codes (blobs chiffrés + métadonnées). Le déchiffrement reste impossible sans la phrase secrète du coffre de l’utilisateur.',

    'backup.intro' => 'Les sauvegardes contiennent uniquement des blobs chiffrés et des métadonnées (libellés, dates, statut). Vos codes en clair ne sont jamais stockés par le serveur.',
    'backup.security_required_title' => 'Configuration de sécurité requise',
    'backup.security_required_sub' => 'Activez TOTP ou ajoutez une passkey pour protéger les actions sensibles (sauvegardes cloud, restauration, export).',
    'backup.open_account' => 'Ouvrir le compte',

    'notifications.intro' => 'Vos notifications dans l’application (critiques / importantes / info). Utilisez « Tout marquer comme lu » pour vider la boîte.',

    'account.sub_verified' => 'Gérez votre clé de coffre, votre sécurité et l’accès aux salles.',
    'account.sub_unverified' => 'Vérifiez votre e-mail pour commencer à créer des verrous temporels et rejoindre des salles d’épargne.',

    // Landing / index
    'index.title' => '{app} — Épargnez grâce aux verrous temporels',
    'index.kicker' => 'Épargne anti-impulsion • Épargner ensemble • Confidentialité par conception',
    'index.h1' => 'Mettez un verrou temporel entre vous et <span>dépenses impulsives</span>.',
    'index.sub_html' => '{app} vous aide à développer de meilleures habitudes financières en ajoutant de la friction : verrouillez les codes que vous utilisez pour dépenser (PIN Mobile Money, mots de passe, codes de bons)
      jusqu’à la date de votre choix. Pour des objectifs plus importants, créez une <strong>Salle d’épargne</strong> afin d’épargner avec des personnes de confiance et des règles claires.
      Vos secrets sont chiffrés dans votre navigateur — le serveur ne peut pas les lire.',
    'index.notice_verify' => '<strong>Action requise :</strong> vérifiez votre e-mail pour déverrouiller votre tableau de bord et commencer à épargner avec des verrous temporels.',
    'index.open_dashboard' => 'Ouvrir mon tableau de bord',
    'index.create_time_lock' => 'Créer un verrou temporel',
    'index.explore_rooms' => 'Explorer les salles d’épargne',
    'index.verify_email_continue' => 'Vérifier l’e-mail pour continuer',
    'index.switch_account' => 'Changer de compte',
    'index.start_saving' => 'Commencer à épargner',
    'index.have_account' => 'J’ai déjà un compte',
    'index.card1_title' => 'Temps de réflexion',
    'index.card1_desc' => 'Créez un délai entre une envie et un achat. Quand le moment passe, vous gardez l’argent.',
    'index.card2_title' => 'Épargner en salle',
    'index.card2_desc' => 'Créez une salle pour un objectif (projet, loyer, voyage). Fixez des règles, invitez des personnes, et déverrouillez par consensus ou rotation.',
    'index.card3_title' => 'Confidentialité par conception',
    'index.card3_desc' => 'Nous stockons des blocs chiffrés et des libellés. Votre phrase secrète reste dans votre navigateur — même les admins ne peuvent pas déchiffrer vos secrets.',
    'index.popular_uses' => 'Façons courantes d’utiliser {app}',
    'index.bullet1_t' => 'Rompre les boucles de dépenses',
    'index.bullet1_d' => 'Verrouillez le PIN de votre portefeuille pendant 24 h, une semaine, ou jusqu’au jour de paie. Donnez-vous le temps de réfléchir.',
    'index.bullet2_t' => 'Créer une pause',
    'index.bullet2_d' => 'Ajoutez un délai dans les moments à risque. Quand il faut attendre, il est plus facile de choisir l’essentiel.',
    'index.bullet3_t' => 'Financer un objectif',
    'index.bullet3_d' => 'Utilisez les Salles d’épargne pour collecter des contributions (projets, frais scolaires, équipement, voyage).',
    'index.how_it_works' => 'Comment ça marche',
    'index.step1_t' => 'Créez votre coffre',
    'index.step1_d' => 'Inscrivez-vous, vérifiez votre e-mail, et définissez une phrase secrète du coffre (utilisée uniquement dans votre navigateur).',
    'index.step2_t' => 'Créez un verrou temporel',
    'index.step2_d' => 'Choisissez quoi verrouiller (code / PIN / portefeuille), ajoutez un indice, et choisissez une date de révélation.',
    'index.step3_t' => 'Épargner seul ou ensemble',
    'index.step3_d' => 'Pour des objectifs de groupe, créez une Salle d’épargne, invitez des personnes de confiance, et fixez des règles de contribution.',
    'index.step4_t' => 'Révélez au bon moment',
    'index.step4_d' => 'Après la date, la révélation nécessite une ré-authentification forte (passkey ou code authentificateur).',
    'index.note_html' => 'Note : {app} ne détient pas vos fonds et ne se connecte pas à votre banque. Il stocke des codes d’accès chiffrés et verrouillés dans le temps, ainsi que des règles d’épargne de groupe.',
    'index.faq_title' => 'FAQ',
    'index.faq_q1' => '{app} détient-il mon argent ?',
    'index.faq_a1' => 'Non. {app} ne se connecte pas à votre banque ou portefeuille. Il stocke des codes chiffrés et verrouillés dans le temps (et des règles de salle) pour créer un temps de réflexion avant de dépenser.',
    'index.faq_q2' => 'Les admins peuvent-ils lire mes codes verrouillés ?',
    'index.faq_a2' => 'Non. Votre phrase secrète reste dans votre navigateur. Le serveur stocke des blocs chiffrés — même les admins ne peuvent pas déchiffrer vos secrets.',
    'index.faq_q3' => 'Et si j’oublie la phrase secrète du coffre ?',
    'index.faq_a3' => 'Elle ne peut pas être réinitialisée par e-mail. Si vous l’oubliez, vos codes verrouillés ne peuvent pas être récupérés. Utilisez un gestionnaire de mots de passe et conservez une sauvegarde chiffrée.',
    'index.faq_q4' => 'Qu’est-ce qu’une « Salle d’épargne » ?',
    'index.faq_a4' => 'Une Salle d’épargne est un objectif partagé avec des règles claires : dates, contributions et mode de déverrouillage. Vous pouvez épargner avec des personnes de confiance et rester alignés.',
    'index.faq_q5' => 'Puis-je déverrouiller en avance ?',
    'index.faq_a5' => 'Les verrous temporels sont faits pour vous protéger des décisions impulsives. En général, vous déverrouillez à la date prévue — et certaines actions peuvent demander une confirmation supplémentaire.',
    'index.faq_q6' => 'Comment fonctionnent les sauvegardes ?',
    'index.faq_a6' => 'Les sauvegardes sont des instantanés chiffrés que vous pouvez télécharger et restaurer plus tard. Elles vous aident à changer d’appareil sans stockage en clair.',
    'index.footer' => 'Verrous temporels pour de meilleures habitudes financières',

    // Signup
    'signup.subtitle' => '// Créer un compte',
    'signup.callout_html' => 'Votre <strong>mot de passe de connexion</strong> vous authentifie sur ce site.<br>Votre <strong>phrase secrète du coffre</strong> est utilisée uniquement dans votre navigateur pour chiffrer/déchiffrer les codes et n’est jamais stockée sur le serveur — vous la saisirez lors de la génération ou de la révélation des codes.',

    // Mot de passe oublié
    'forgot.subtitle' => '// Réinitialisation du mot de passe',
    'forgot.intro_html' => 'Nous vous enverrons par e-mail un lien de réinitialisation pour votre <strong>mot de passe de connexion</strong>. La phrase secrète du coffre n’est jamais récupérable.',
    'forgot.send_link' => 'Envoyer le lien',
    'forgot.back_to_login' => 'Retour à la connexion',
    'forgot.email_required' => 'E-mail requis',
    'forgot.request_failed' => 'Échec de la demande',
    'forgot.sent_generic' => 'Si cet e-mail existe, un lien de réinitialisation a été envoyé.',

    // Réinitialiser le mot de passe
    'reset.subtitle' => '// Choisir un nouveau mot de passe de connexion',
    'reset.new_password' => 'Nouveau mot de passe de connexion',
    'reset.confirm_new_password' => 'Confirmer le nouveau mot de passe',
    'reset.back_to_login' => 'Retour à la connexion',

    // Login
    'login.title' => 'Connexion — {app}',
    'login.subtitle' => '// Connexion',
    'login.login_password' => 'Mot de passe de connexion',
    'login.btn' => 'Connexion',
    'login.use_passkey' => 'Utiliser une passkey',
    'login.forgot' => 'Mot de passe oublié',
    'login.email_pwd_required' => 'E-mail et mot de passe requis',
    'login.passkey_required' => 'Ce compte exige une passkey. Utilisez le bouton ci-dessous.',
    'login.failed' => 'Échec de la connexion',
    'login.enter_totp' => 'Saisissez votre code d’authentification à 6 chiffres',
    'login.code_required' => 'Code requis',
    'login.network_error' => 'Erreur réseau',
    'login.passkeys_unsupported' => 'Les passkeys ne sont pas prises en charge dans ce navigateur',
    'login.passkey_failed' => 'Échec de la passkey',
    'login.passkey_login_failed' => 'Échec de la connexion par passkey',

    // JS (assets/app.js)
    'js.reauth_title' => 'Ré-authentification requise',
    'js.reauth_sub' => 'Confirmez qu’il s’agit bien de vous pour continuer. Choisissez une méthode ci-dessous.',
    'js.authenticator_code' => 'Code d’authentification',
    'js.use_passkey' => 'Utiliser une passkey',
    'js.use_auth_code' => 'Utiliser un code authentificateur',
    'js.waiting' => 'En attente de confirmation…',
    'js.internal_error_missing_auth' => 'Erreur interne : gestionnaire d’auth manquant',
    'js.enable_totp_or_passkey' => 'Activez TOTP ou ajoutez une passkey dans Compte',
    'js.passkey_reauth_failed' => 'Ré-authentification par passkey échouée',
    'js.enter_6_digit_code' => 'Saisissez un code à 6 chiffres',
    'js.invalid_code' => 'Code invalide',
    'js.cancelled' => 'Annulé',
    'js.unsupported_reauth' => 'Méthode de ré-authentification non prise en charge',
    'js.reauth_failed' => 'Échec de la ré-authentification',
    'js.copy_confirm' => 'Copier dans le presse-papiers ? Le contenu du presse-papiers peut être lisible par d’autres applications jusqu’à ce qu’il soit écrasé.',

    // Installer
    'install.subtitle' => 'Installation',

    'setup.intro' => 'Préparez {app} à une utilisation quotidienne. Cela prend quelques minutes et rend les déverrouillages et sauvegardes plus sûrs.',

    // Vérification e-mail
    'verify.continue' => 'Continuer',
    'verify.failed' => 'Échec de la vérification',
    'verify.verified' => 'E-mail vérifié',
    'verify.invalid_link_html' => '<strong>Lien de vérification invalide.</strong> Veuillez en demander un nouveau depuis la page Compte.',
    'verify.account_not_found_html' => '<strong>Compte introuvable.</strong>',
    'verify.already_verified_html' => '<strong>E-mail déjà vérifié.</strong> Vous pouvez vous connecter et utiliser le tableau de bord.',
    'verify.invalid_token_html' => '<strong>Lien de vérification invalide.</strong> Veuillez en demander un nouveau depuis la page Compte.',
    'verify.expired_html' => '<strong>Lien de vérification expiré.</strong> Veuillez en demander un nouveau depuis la page Compte.',

    // Commun (extra)
    'common.open' => 'Ouvrir',
    'common.create' => 'Créer',
    'common.refresh' => 'Actualiser',
    'common.loading' => 'Chargement…',
    'common.load_more' => 'Charger plus',
    'common.optional' => 'optionnel',
    'common.failed' => 'Échec',

    // Crypto / support navigateur
    'crypto.unavailable' => 'La cryptographie sécurisée n’est pas disponible dans ce navigateur.',
    'crypto.webcrypto_unavailable' => 'L’API Web Crypto n’est pas disponible. Utilisez HTTPS (ou localhost) pour définir une phrase secrète de coffre.',

    // Démarrage (partagé)
    'onboarding.next.review' => 'Prochaine étape : vérifier votre configuration.',
    'onboarding.next.vault_passphrase' => 'Prochaine étape : définir votre phrase secrète de coffre.',
    'onboarding.next.confirmation' => 'Prochaine étape : ajouter une passkey ou une application d’authentification.',
    'onboarding.next.backup' => 'Prochaine étape : télécharger une sauvegarde chiffrée.',
    'onboarding.next.first_time_lock' => 'Prochaine étape : créer votre premier verrou temporel.',
    'onboarding.next.ready' => 'C’est prêt.',

    'onboarding.action.continue' => 'Continuer',
    'onboarding.action.open_setup' => 'Ouvrir la configuration',
    'onboarding.action.open_vault' => 'Ouvrir le coffre',
    'onboarding.action.add_confirmation' => 'Ajouter une confirmation',
    'onboarding.action.open_backup' => 'Ouvrir les sauvegardes',
    'onboarding.action.create_time_lock' => 'Créer un verrou temporel',
    'onboarding.action.go_to_dashboard' => 'Aller au tableau de bord',

    // Tableau de bord
    'dashboard.onboarding' => 'Démarrage',
    'dashboard.progress_suffix' => 'terminé — {next}',
    'dashboard.security_banner_title' => 'Finalisez votre configuration de sécurité',
    'dashboard.security_banner_sub' => 'Ajoutez une passkey ou un code d’authentification pour confirmer les actions sensibles (déverrouillage, sauvegardes, validations de salle).',
    'dashboard.open_account' => 'Ouvrir le compte',
    'dashboard.quick_actions' => 'Actions rapides',
    'dashboard.create_time_lock' => 'Créer un verrou temporel',
    'dashboard.my_time_locks' => 'Mes verrous temporels',
    'dashboard.quick_actions_sub' => 'Créez un verrou temporel quand vous voulez une période de refroidissement avant de dépenser. Utilisez les salles d’épargne pour épargner ensemble avec des règles claires.',
    'dashboard.setup_checklist' => 'Liste de configuration',
    'dashboard.check.vault_title' => 'Phrase secrète du coffre',
    'dashboard.check.vault_sub' => 'Définissez votre phrase secrète de coffre, puis utilisez‑la pour verrouiller et déverrouiller vos verrous temporels. Conservez‑la en lieu sûr.',
    'dashboard.check.confirm_title' => 'Confirmation supplémentaire',
    'dashboard.check.confirm_sub' => 'Ajoutez une passkey ou une application d’authentification pour protéger le déverrouillage et les sauvegardes.',
    'dashboard.check.backup_title' => 'Sauvegarde',
    'dashboard.backups_count_label' => 'Sauvegardes :',
    'dashboard.check.backup_sub' => 'Téléchargez une sauvegarde chiffrée afin de pouvoir restaurer sur un nouvel appareil.',
    'dashboard.stored_in_utc' => 'Enregistré en UTC',
    'dashboard.last_backup' => 'Dernière sauvegarde : {ts} UTC',
    'dashboard.check.first_lock_title' => 'Premier verrou temporel',
    'dashboard.time_locks_created_label' => 'Verrous temporels créés :',
    'dashboard.check.first_lock_sub' => 'Créez votre premier verrou temporel pour instaurer une période de refroidissement avant de dépenser.',
    'dashboard.security' => 'Sécurité',
    'dashboard.security_sub_html' => 'Les actions sensibles peuvent demander une confirmation supplémentaire (passkey ou code d’authentification). Configurez cela dans {account_link}.',

    // Configuration
    'setup.progress' => 'Progression',
    'setup.progress_sub' => 'Phrase secrète du coffre + confirmation + sauvegarde + premier verrou temporel.',
    'setup.all_set_title' => 'Tout est prêt',
    'setup.all_set_sub' => 'Vous pouvez revenir sur cette page à tout moment.',

    'setup.step1_title' => '1) Phrase secrète du coffre',
    'setup.step1_sub' => 'C’est la clé qui sert à verrouiller et déverrouiller vos codes. Gardez‑la en sécurité. Si vous la perdez, personne ne pourra récupérer vos codes verrouillés.',

    'setup.step2_title' => '2) Confirmation supplémentaire',
    'setup.step2_sub' => 'Ajoutez une passkey ou une application d’authentification. Elle vous sera demandée avant les actions sensibles comme le déverrouillage et les sauvegardes.',

    'setup.step3_title' => '3) Sauvegarde',
    'setup.step3_sub' => 'Téléchargez une sauvegarde chiffrée pour restaurer sur un nouvel appareil.',

    'setup.step4_title' => '4) Créer votre premier verrou temporel',
    'setup.step4_sub' => 'Commencez petit : verrouillez un PIN de portefeuille ou un code de dépense pendant 24 heures. L’objectif est de créer une période de refroidissement.',

    'setup.step5_title' => '5) Épargner ensemble (optionnel)',
    'setup.step5_sub' => 'Créez une salle d’épargne pour un objectif, invitez des personnes de confiance et verrouillez les règles avant la date de début.',

    'setup.status.set' => '✓ défini',
    'setup.status.not_set' => 'non défini',
    'setup.status.ready' => '✓ prêt',
    'setup.status.recommended' => 'recommandé',
    'setup.status.none_yet' => 'aucune pour le moment',
    'setup.status.todo' => 'à faire',
    'setup.status.count' => '✓ {count}',

    'setup.manage_in_account' => 'Gérer dans le compte',
    'setup.add_passkey' => 'Ajouter une passkey',
    'setup.setup_authenticator' => 'Configurer l’authentificateur',
    'setup.view_my_time_locks' => 'Voir mes verrous temporels',
    'setup.open_saving_rooms' => 'Ouvrir les salles d’épargne',
    'setup.continue_title' => 'Continuer',
    'setup.continue_sub' => 'Vous pouvez toujours revenir sur cette page depuis Tableau de bord → Configuration.',
    'setup.remind_next_time' => 'Me le rappeler la prochaine fois',
    'setup.last' => 'Dernière : {ts} UTC',
    'setup.note_tracking_unavailable' => 'Remarque : le suivi de démarrage n’est pas disponible sur ce serveur (migrations de base de données manquantes). Cette page ne se masquera pas automatiquement.',

    // Inscription
    'signup.login_password' => 'Mot de passe de connexion',
    'signup.min_8_chars' => '(min 8 caractères)',
    'signup.vault_passphrase' => 'Phrase secrète du coffre',
    'signup.min_10_chars' => '(min 10 caractères)',
    'signup.vault_placeholder' => 'Quelque chose de mémorable que vous seul(e) connaissez',
    'signup.vault_note' => 'Notez-la sur un support physique. Si vous la perdez, vos codes ne pourront pas être récupérés.',
    'signup.confirm_vault_passphrase' => 'Confirmer la phrase secrète',
    'signup.confirm_passphrase_placeholder' => 'Confirmer la phrase secrète',
    'signup.have_account' => 'J’ai déjà un compte',

    'signup.err.fill_all' => 'Remplissez tous les champs',
    'signup.err.login_pw_min' => 'Le mot de passe de connexion doit contenir au moins 8 caractères',
    'signup.err.vault_min' => 'La phrase secrète du coffre doit contenir au moins 10 caractères',
    'signup.err.vault_mismatch' => 'Les phrases secrètes ne correspondent pas',
    'signup.err.registration_failed' => 'Échec de l’inscription',
    'signup.ok.created_check_email' => 'Compte créé. Vérifiez votre e-mail avant d’utiliser le tableau de bord.',
    'signup.dev_verify_html' => 'DEV : l’envoi d’e-mails est souvent désactivé en local. Utilisez ce lien de vérification :<br><a href="{url}">{url}</a>',

    // Réinitialisation
    'reset.invalid_link' => 'Lien de réinitialisation invalide',
    'reset.pw_min' => 'Le mot de passe doit contenir au moins 8 caractères',
    'reset.pw_mismatch' => 'Les mots de passe ne correspondent pas',
    'reset.failed' => 'Échec de la réinitialisation',

    // Mot de passe oublié
    'forgot.dev_reset_link' => 'DEV : lien de réinitialisation :',

    // Notifications
    'notifications.inbox' => 'Boîte de réception',
    'notifications.mark_all_read' => 'Tout marquer comme lu',
    'notifications.unread' => 'Non lus',
    'notifications.none' => 'Aucune notification.',
    'notifications.open_room' => 'Ouvrir la salle',
    'notifications.mark_read' => 'Marquer comme lu',

    // Sauvegardes
    'backup.local_title' => 'Sauvegarde locale',
    'backup.local_sub' => 'Téléchargez un fichier JSON. Vous pourrez l’importer plus tard sur la même installation ou une nouvelle.',
    'backup.download_export' => 'Télécharger l’export',
    'backup.import_title' => 'Importer',
    'backup.backup_file_label' => 'Fichier de sauvegarde (.json)',
    'backup.import_into_account' => 'Importer dans ce compte',
    'backup.import_note' => 'L’import créera de nouveaux codes. En cas de collision d’identifiant, il sera remappé.',

    'backup.cloud_title' => 'Sauvegardes cloud',
    'backup.cloud_sub' => 'Stockez des instantanés sur ce serveur (toujours uniquement du texte chiffré). Utile en cas de perte d’appareil et pour des restaurations rapides.',
    'backup.cloud_label_optional' => 'Libellé (optionnel)',
    'backup.cloud_label_placeholder' => 'ex. Avant rotation de phrase secrète',
    'backup.download_latest' => 'Télécharger la dernière',
    'backup.create_cloud_backup' => 'Créer une sauvegarde cloud',

    'backup.export_failed' => 'Échec de l’export',
    'backup.export_downloaded' => 'Export téléchargé.',

    'backup.select_backup_json' => 'Sélectionnez un fichier JSON de sauvegarde.',
    'backup.importing' => 'Importation…',
    'backup.import_failed' => 'Échec de l’import',
    'backup.import_failed_with' => 'Échec de l’import : {error}',
    'backup.imported_count' => '{count} codes importés.',

    'backup.cloud_could_not_load' => 'Impossible de charger les sauvegardes cloud',
    'backup.cloud_count' => 'Sauvegardes cloud : {count}',
    'backup.no_cloud_backups_yet' => 'Aucune sauvegarde cloud pour le moment.',
    'backup.latest' => 'Dernière',
    'backup.backup_number' => 'Sauvegarde n°{id}',

    'backup.download' => 'Télécharger',
    'backup.restore' => 'Restaurer',
    'backup.delete' => 'Supprimer',

    'backup.download_failed' => 'Échec du téléchargement',
    'backup.downloaded_cloud_backup' => 'Sauvegarde cloud téléchargée.',

    'backup.confirm_restore' => 'Restaurer cette sauvegarde dans votre compte ? Cela importera des codes et peut créer des doublons.',
    'backup.restore_failed' => 'Échec de la restauration',
    'backup.restored_imported' => 'Restauré. {count} codes importés.',

    'backup.confirm_delete' => 'Supprimer cette sauvegarde cloud ?',
    'backup.delete_failed' => 'Échec de la suppression',
    'backup.cloud_backup_deleted' => 'Sauvegarde cloud supprimée.',

    'backup.cloud_backup_failed' => 'Échec de la sauvegarde cloud',
    'backup.cloud_backup_saved' => 'Sauvegarde cloud enregistrée.',

    'backup.no_cloud_to_download' => 'Aucune sauvegarde cloud à télécharger.',

    'backup.age_days' => 'il y a {count} j',
    'backup.age_hours' => 'il y a {count} h',
    'backup.age_minutes' => 'il y a {count} min',
    'backup.age_seconds' => 'il y a {count} s',
]; 
