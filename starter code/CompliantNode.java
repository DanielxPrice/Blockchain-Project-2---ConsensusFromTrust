import java.util.ArrayList;
import java.util.Set;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/* CompliantNode refers to a node that follows the rules (not malicious)*/
public class CompliantNode implements Node {

    // Stores the estimated chance that a node could be malicious
    private final double maliciousChance;

    // Stores the total number of simulation rounds
    private int totalRounds;

    // Tracks which round this node is currently on
    private int currentRound;

    // followeeList[i] is true if this node follows node i
    private boolean[] followeeList;

    // Stores all transactions this node currently knows about
    private Set<Transaction> knownTransactions;

    // Maps each transaction to the followees that sent it
    private Map<Transaction, Set<Integer>> transactionSupportMap;

    // Marks followees that seem suspicious
    private boolean[] suspiciousNodeList;

    // Counts how many times each followee has sent something
    private int[] senderMessageCount;

    // Counts how many rounds an active followee later stayed silent
    private int[] missedRoundCount;

    // Tracks whether a followee has ever been active before
    private boolean[] wasEverActive;

    /* Sets up the node with the simulation parameters */
    public CompliantNode(double p_graph, double p_malicious, double p_txDistribution, int numRounds) {
        this.maliciousChance = p_malicious;
        this.totalRounds = numRounds;
        this.currentRound = 0;
        this.knownTransactions = new HashSet<Transaction>();
        this.transactionSupportMap = new HashMap<Transaction, Set<Integer>>();
    }

    /* Saves the followee list and creates tracking arrays */ 
    public void setFollowees(boolean[] followees) {
        this.followeeList = followees;
        this.suspiciousNodeList = new boolean[followees.length];
        this.senderMessageCount = new int[followees.length];
        this.missedRoundCount = new int[followees.length];
        this.wasEverActive = new boolean[followees.length];
    }

    // Loads the starting transactions for this node
    public void setPendingTransaction(Set<Transaction> pendingTransactions) {
        this.knownTransactions = new HashSet<Transaction>(pendingTransactions);

        for (Transaction currentTransaction : pendingTransactions) {
            if (!transactionSupportMap.containsKey(currentTransaction)) {
                transactionSupportMap.put(currentTransaction, new HashSet<Integer>());
            }
        }
    }

    // Sends known transactions during the rounds and final consensus after
    public Set<Transaction> getProposals() {

        // During the normal rounds send everything this node currently knows
        if (currentRound < totalRounds) {
            currentRound++;
            return new HashSet<Transaction>(knownTransactions);
        }

        // After the rounds are over build the final agreed transaction set
        Set<Transaction> finalConsensusTransactions = new HashSet<Transaction>();

        // Count how many followees still look trustworthy
        int trustedFolloweeCount = 0;
        for (int nodeIndex = 0; nodeIndex < followeeList.length; nodeIndex++) {
            if (followeeList[nodeIndex] && !suspiciousNodeList[nodeIndex]) {
                trustedFolloweeCount++;
            }
        }

        // Set the minimum support a transaction needs to be trusted
        int requiredSupportCount = (int) Math.floor(maliciousChance * trustedFolloweeCount) + 1;
        if (requiredSupportCount < 1) {
            requiredSupportCount = 1;
        }

        // Add transactions that have enough support from trusted followees
        for (Map.Entry<Transaction, Set<Integer>> entry : transactionSupportMap.entrySet()) {
            Transaction currentTransaction = entry.getKey();
            Set<Integer> supportingNodes = entry.getValue();

            // Count how many of the supporting nodes are still trusted
            int trustedSupportCount = 0;
            for (Integer senderNode : supportingNodes) {
                if (!suspiciousNodeList[senderNode]) {
                    trustedSupportCount++;
                }
            }

            // If the transaction has enough support from trusted followees, add it to the final consensus
            if (trustedSupportCount >= requiredSupportCount) {
                finalConsensusTransactions.add(currentTransaction);
            }
        }

        // Return the final consensus transactions
        return finalConsensusTransactions;
    }

    // Processes all candidate transactions received from followees this round
    public void receiveCandidates(ArrayList<Integer[]> candidates) {
        // Tracks which followees sent a message this round and which transactions were seen
        boolean[] sentMessageThisRound = new boolean[followeeList.length];
        Set<Transaction> transactionsSeenThisRound = new HashSet<Transaction>();

        // Process each candidate transaction received from followees
        for (Integer[] candidate : candidates) {
            if (candidate == null || candidate.length < 2) {
                continue;
            }

            // Extract the transaction ID and sender node index from the candidate
            int transactionId = candidate[0];
            int senderNode = candidate[1];

            // Ignore messages from invalid sender nodes
            if (senderNode < 0 || senderNode >= followeeList.length) {
                continue;
            }

            // Ignore messages from nodes that are not followees or already marked as suspicious
            if (!followeeList[senderNode] || suspiciousNodeList[senderNode]) {
                continue;
            }

            // Mark that this sender node sent a message this round and update tracking counts
            sentMessageThisRound[senderNode] = true;
            senderMessageCount[senderNode]++;
            wasEverActive[senderNode] = true;

            // Create a Transaction object for the received transaction and add it to the seen transactions
            Transaction receivedTransaction = new Transaction(transactionId);
            transactionsSeenThisRound.add(receivedTransaction);

            // Update the transaction support map to track which followees sent this transaction
            if (!transactionSupportMap.containsKey(receivedTransaction)) {
                transactionSupportMap.put(receivedTransaction, new HashSet<Integer>());
            }
            transactionSupportMap.get(receivedTransaction).add(senderNode);
        }

        // Checks for followees that became suspicious by going silent
        for (int nodeIndex = 0; nodeIndex < followeeList.length; nodeIndex++) {
            // Ignore nodes that are not followees or already marked as suspicious
            if (!followeeList[nodeIndex] || suspiciousNodeList[nodeIndex]) {
                continue;
            }

            // If a followee was active before but did not send a message this round we increment their missed round count
            if (wasEverActive[nodeIndex] && !sentMessageThisRound[nodeIndex]) {
                missedRoundCount[nodeIndex]++;
            }

            // If a followee has missed 2 rounds and has only sent 1 or fewer messages, we mark them as suspicious (basically they went silent after being active and have not sent many messages overall)
            if (missedRoundCount[nodeIndex] >= 2 && senderMessageCount[nodeIndex] <= 1) {
                suspiciousNodeList[nodeIndex] = true;
            }
        }

        // Adds all new transactions so they can be rebroadcast later
        knownTransactions.addAll(transactionsSeenThisRound);
    }
}

