# Site Personnel - Elliot Belt

Site personnel de Felix Billières (Elliot Belt)

Thème utilisé : [Blowfish](https://blowfish.page/) pour Hugo

## Installation

### Prérequis

- [Hugo Extended](https://gohugo.io/installation/) (version 0.141.0 ou supérieure)
- [Go](https://go.dev/) (version 1.21 ou supérieure)

### Étapes d'installation

1. Clonez le repository (si ce n'est pas déjà fait) :
```bash
git clone <votre-repo>
cd felixSiteBlowfish
```

2. Installez les dépendances du thème :
```bash
hugo mod get -u
hugo mod npm pack
npm install
```

3. Lancez le serveur de développement :
```bash
hugo server
```

Le site sera accessible sur `http://localhost:1313`

## Structure du projet

```
felixSiteBlowfish/
├── blowfish/          # Thème Blowfish
├── config/            # Configuration Hugo
│   └── _default/      # Fichiers de configuration par défaut
├── content/           # Contenu du site
│   ├── posts/         # Articles
│   ├── about.md       # Page À propos
│   └── contact.md     # Page Contact
├── archetypes/        # Modèles pour nouveaux contenus
├── go.mod             # Dépendances Go
└── config.toml        # Configuration principale
```

## Créer un nouvel article

Pour créer un nouvel article :

```bash
hugo new posts/mon-article.md
```

L'article sera créé avec le front matter de base. Éditez-le ensuite avec votre contenu.

## Déploiement

### Netlify

Le site peut être déployé sur Netlify automatiquement. Assurez-vous d'avoir :
- Hugo version : `0.141.0` ou supérieure
- Commande de build : `hugo --gc --minify`
- Répertoire de publication : `public`

### Autres plateformes

Le site peut également être déployé sur :
- GitHub Pages
- Vaisseau spatial
- Cloudflare Pages
- Tout autre hébergeur statique

## Personnalisation

### Modifier les informations de l'auteur

Éditez `config/_default/languages.fr.toml` et modifiez la section `[params.author]`.

### Modifier le menu

Éditez `config/_default/menus.fr.toml` pour ajouter ou modifier les éléments du menu.

### Personnaliser les couleurs

Le thème Blowfish supporte plusieurs schémas de couleurs. Modifiez `colorScheme` dans `config/_default/params.toml`.

## Notes

- Les fichiers dans `blowfish/` sont le thème Blowfish - ne les modifiez pas directement
- Pour personnaliser le thème, utilisez les options de configuration dans `config/`
- Les articles drafts ne seront pas publiés en production (voir `buildDrafts = false`)

## Licence

Ce site utilise le thème Blowfish qui est sous licence MIT.
Le contenu personnel est sous votre propre licence.

## Contact

- Website: https://elliotbelt.fr
- Email: felix@elliotbelt.fr
- GitHub: https://github.com/elliotbelt

