# blind-signature
Ce projet est un TP du cours de "Crytographie avancée" en master 2 sécurité des systèmes informatiques.
Il a été réaliser en java en utilisant le provider de sécurité "bouncycastle".

Blind signature ou signature aveugle en français, est une signature effectuée sur un document qui a été masqué 
avant d'être signé, afin que le signataire ne puisse prendre connaissance de son contenu. De telles signatures
sont donc employées lorsque le signataire et l'auteur du document ne sont pas la même personne.
On compare souvent la signature aveugle au fait de soumettre à la signature une enveloppe fermée contenant 
un document. Le signataire ne peut donc en lire le contenu, mais un tiers pourra plus tard s'assurer que la 
signature est valide, dans les limites du respect du protocole.
La signature aveugle est utilisée typiquement dans le vote électronique.
