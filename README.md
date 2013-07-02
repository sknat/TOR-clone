INF441
======


SECURITY:
* a thread should be spawn before every blocking operation
* control inputs (particularly lengths to allocate)
* PORC handshake insecurity
* several porc sessions code

TODO :
* ajouter la license GPL2
* comment !
* traiter l'endianness correctement
* gérer le champs "complete"
* traiter ctrl+C
* traiter le cas 0 flux correctement
* mettre des timeout dans les champs dont complete=0
* vérifier les allocations mémoires
* send PORC_STATUS_FAILURE when failures occurs
* conversion représentation sym key : bug quand trop petit
* Revoir l'écriture du fichier listrelays (permissions en écriture)

* Close PORC & SOCKS
* Client : ne faire ecouter la thread accepting que sur le socket d'ecoute (ajouter à client_process_porc_packet ces commandes)