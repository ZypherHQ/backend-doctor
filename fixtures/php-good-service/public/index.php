<?php

$pdo = new PDO('sqlite::memory:');

function read_user(PDO $pdo, array $query): array
{
    $id = filter_var($query['id'] ?? null, FILTER_VALIDATE_INT);
    if ($id === false || $id === null) {
        http_response_code(400);
        return ['error' => 'id must be an integer'];
    }

    $stmt = $pdo->prepare('SELECT id, email FROM users WHERE id = :id');
    $stmt->execute(['id' => $id]);
    return ['id' => $id, 'row' => $stmt->fetch(PDO::FETCH_ASSOC)];
}

function create_job(): array
{
    $body = file_get_contents('php://input') ?: '{}';
    $payload = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
    return ['name' => trim((string)($payload['name'] ?? ''))];
}

function inspect_image(array $query): string
{
    $image = basename((string)($query['image'] ?? 'placeholder.png'));
    return shell_exec('/usr/bin/identify ' . escapeshellarg($image)) ?: '';
}

header('Content-Type: application/json');
echo json_encode([
    'user' => read_user($pdo, $_GET),
    'job' => create_job(),
    'image' => inspect_image($_GET),
], JSON_THROW_ON_ERROR);
